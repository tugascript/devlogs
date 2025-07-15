// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	usersAuthLocation string = "users_auth"

	forgotUserMessage string = "Reset password email sent if user exists"
	resetUserMessage  string = "Password reset successfully"
)

func mapAuthTokenTypeToKeyType(tokenType tokens.AuthTokenType) (database.TokenKeyType, error) {
	switch tokenType {
	case tokens.AuthTokenTypeAccess:
		return database.TokenKeyTypeAccess, nil
	case tokens.AuthTokenTypeRefresh:
		return database.TokenKeyTypeRefresh, nil
	case tokens.AuthTokenTypeClientCredentials:
		return database.TokenKeyTypeClientCredentials, nil
	default:
		return "", fmt.Errorf("unsupported token type: %s", tokenType)
	}
}

func mapPurposeTokenTypeToKeyType(tokenType tokens.PurposeTokenType) (database.TokenKeyType, error) {
	switch tokenType {
	case tokens.PurposeTokenTypeConfirmation:
		return database.TokenKeyTypeEmailVerification, nil
	case tokens.PurposeTokenTypeReset:
		return database.TokenKeyTypePasswordReset, nil
	case tokens.PurposeTokenTypeOAuth:
		return database.TokenKeyTypeOauthAuthorization, nil
	case tokens.PurposeTokenTypeTwoFA:
		return database.TokenKeyType2faAuthentication, nil
	default:
		return "", fmt.Errorf("unsupported purpose token type: %s", tokenType)
	}
}

type ProcessUserAuthHeaderOptions struct {
	RequestID  string
	AuthHeader string
	AccountID  int32
	TokenType  tokens.AuthTokenType
}

func (s *Services) ProcessUserAuthHeader(
	ctx context.Context,
	opts ProcessUserAuthHeaderOptions,
) (tokens.UserAuthClaims, tokens.AppClaims, []database.Scopes, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ProcessUserAuthHeader").With(
		"tokenType", opts.TokenType,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Processing user auth header...")

	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, serviceErr
	}

	keyType, err := mapAuthTokenTypeToKeyType(opts.TokenType)
	if err != nil {
		logger.ErrorContext(ctx, "Unsupported token type", "error", err)
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, exceptions.NewServerError()
	}

	userClaims, appClaims, scopes, _, _, err := s.jwt.VerifyUserAuthToken(
		token,
		utils.SupportedCryptoSuiteES256,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   keyType,
		}),
	)
	if err != nil {
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return userClaims, appClaims, scopes, nil
}

type ProcessUserPurposeHeaderOptions struct {
	RequestID  string
	AuthHeader string
	AccountID  int32
	TokenType  tokens.PurposeTokenType
}

func (s *Services) ProcessUserPurposeHeader(
	ctx context.Context,
	opts ProcessUserPurposeHeaderOptions,
) (tokens.UserPurposeClaims, tokens.AppClaims, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ProcessUserPurposeHeader").With(
		"tokenType", opts.TokenType,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Processing user purpose header...")
	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, serviceErr
	}

	keyType, err := mapPurposeTokenTypeToKeyType(opts.TokenType)
	if err != nil {
		logger.ErrorContext(ctx, "Unsupported token type", "error", err)
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, exceptions.NewServerError()
	}

	userClaims, appClaims, purpose, err := s.jwt.VerifyUserPurposeToken(
		token,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   keyType,
		}),
	)
	if err != nil {
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}
	if purpose != opts.TokenType {
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}

	return userClaims, appClaims, nil
}

type sendUserConfirmationEmailOptions struct {
	requestID          string
	accountID          int32
	accountUsername    string
	appVersion         int32
	appClientID        string
	appName            string
	appConfirmationURI string
}

func (s *Services) sendUserConfirmationEmail(
	ctx context.Context,
	userDTO *dtos.UserDTO,
	opts sendUserConfirmationEmailOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, usersAuthLocation, "sendUserConfirmationEmail").With(
		"accountId", opts.accountID,
		"appClientId", opts.appClientID,
		"userPublicID", userDTO.PublicID,
	)
	logger.InfoContext(ctx, "Sending user confirmation email...")

	token, err := s.jwt.CreateUserPurposeToken(tokens.UserPurposeTokenOptions{
		TokenType:       tokens.PurposeTokenTypeConfirmation,
		AccountUsername: opts.accountUsername,
		UserPublicID:    userDTO.PublicID,
		UserVersion:     userDTO.Version(),
		AppClientID:     opts.appClientID,
		AppVersion:      opts.appVersion,
		Path:            paths.AppsBase + paths.UsersBase + paths.AuthConfirmEmail,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user token", "error", err)
		return exceptions.NewServerError()
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token:     token,
		GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, logger, BuildGetEncryptedAccountJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyTypeEmailVerification,
			AccountID: opts.accountID,
		}),
		GetDEKfn: s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
			requestID: opts.requestID,
			accountID: opts.accountID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign user token", "serviceError", serviceErr)
		return serviceErr
	}

	if err := s.mail.PublishUserConfirmationEmail(ctx, mailer.UserConfirmationEmailOptions{
		RequestID:         opts.requestID,
		AppName:           opts.appName,
		Email:             userDTO.Email,
		ConfirmationURI:   opts.appConfirmationURI,
		ConfirmationToken: signedToken,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish confirmation email", "error", err)
		return exceptions.NewServerError()
	}

	return nil
}

type RegisterUserOptions struct {
	RequestID       string
	AccountID       int32
	AccountUsername string
	AppClientID     string
	AppVersion      int32
	Email           string
	Username        string
	Password        string
	UserData        reflect.Value
}

func (s *Services) RegisterUser(
	ctx context.Context,
	opts RegisterUserOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "RegisterUser").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Registering user...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.AuthProviders, database.AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Invalid Provider")
		return dtos.MessageDTO{}, exceptions.NewForbiddenError()
	}

	userDTO, serviceErr := s.CreateAppUser(ctx, CreateAppUserOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     appDTO.ID(),
		Email:     opts.Email,
		Username:  opts.Username,
		Password:  opts.Password,
		Provider:  AuthProviderUsernamePassword,
		UserData:  opts.UserData,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to register user", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if serviceErr := s.sendUserConfirmationEmail(ctx, &userDTO, sendUserConfirmationEmailOptions{
		requestID:       opts.RequestID,
		accountID:       opts.AccountID,
		accountUsername: opts.AccountUsername,
		appVersion:      appDTO.Version(),
		appClientID:     appDTO.ClientID,
		appName:         appDTO.Name,
		// TODO: add from app type appConfirmationURI: appDTO.ConfirmationURI,
	}); serviceErr != nil {
		return dtos.MessageDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Registered user successfully")
	return dtos.NewMessageDTO("User registered successfully. Confirmation email hasd been sent"), nil
}

func (s *Services) generateFullUserAuthDTO(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountID int32,
	userDTO *dtos.UserDTO,
	appDTO *dtos.AppDTO,
	scopes []database.Scopes,
	accountUsername,
	logSuccessMessage string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	accessToken, err := s.jwt.CreateUserAuthToken(tokens.UserAuthTokenOptions{
		CryptoSuite:     utils.SupportedCryptoSuiteES256,
		TokenType:       tokens.AuthTokenTypeAccess,
		AccountUsername: accountUsername,
		UserPublicID:    userDTO.PublicID,
		UserVersion:     userDTO.Version(),
		UserRoles:       userDTO.UserRoles,
		Scopes:          scopes,
		TokenSubject:    userDTO.PublicID.String(),
		AppClientID:     appDTO.ClientID,
		AppVersion:      appDTO.Version(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	signedAccessToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     accessToken,
		GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, logger, BuildGetEncryptedAccountJWKFnOptions{
			RequestID: requestID,
			KeyType:   database.TokenKeyTypeAccess,
			AccountID: accountID,
		}),
		GetDEKfn: s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
			requestID: requestID,
			accountID: accountID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign access token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	refreshToken, err := s.jwt.CreateUserAuthToken(tokens.UserAuthTokenOptions{
		CryptoSuite:     utils.SupportedCryptoSuiteEd25519,
		TokenType:       tokens.AuthTokenTypeRefresh,
		AccountUsername: accountUsername,
		UserPublicID:    userDTO.PublicID,
		UserVersion:     userDTO.Version(),
		UserRoles:       userDTO.UserRoles,
		Scopes:          scopes,
		TokenSubject:    userDTO.PublicID.String(),
		AppClientID:     appDTO.ClientID,
		AppVersion:      appDTO.Version(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	signedRefreshToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     refreshToken,
		GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, logger, BuildGetEncryptedAccountJWKFnOptions{
			RequestID: requestID,
			KeyType:   database.TokenKeyTypeRefresh,
			AccountID: accountID,
		}),
		GetDEKfn: s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
			requestID: requestID,
			accountID: accountID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign access token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	logger.InfoContext(ctx, logSuccessMessage)
	return dtos.NewFullAuthDTO(signedAccessToken, signedRefreshToken, s.jwt.GetAccessTTL()), nil
}

type ConfirmAuthUserOptions struct {
	RequestID         string
	AccountID         int32
	AccountUsername   string
	AppClientID       string
	AppVersion        int32
	ConfirmationToken string
}

func (s *Services) ConfirmAuthUser(
	ctx context.Context,
	opts ConfirmAuthUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ConfirmAuthUser").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Confirming user...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.AuthProviders, database.AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Invalid Provider", "Provider", AuthProviderUsernamePassword)
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}

	userClaims, appClaims, _, err := s.jwt.VerifyUserPurposeToken(
		opts.ConfirmationToken,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   database.TokenKeyTypeEmailVerification,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.ClientID != opts.AppClientID {
		logger.WarnContext(ctx, "Invalid app client ID", "tokenAppClientId", appClaims.ClientID, "appClientId", opts.AppClientID)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userDTO, serviceErr := s.ConfirmAppUser(ctx, ConfirmAppUserOptions{
		RequestID:    opts.RequestID,
		AccountID:    opts.AccountID,
		UserPublicID: userClaims.UserID,
		UserVersion:  userClaims.UserVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to confirm user", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.generateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		appDTO.DefaultScopes,
		opts.AccountUsername,
		"User confirmed successfully",
	)
}

type GetUserByUsernameOrEmailOptions struct {
	RequestID       string
	AccountID       int32
	UsernameColumn  database.AppUsernameColumn
	UsernameOrEmail string
}

func (s *Services) GetUserByUsernameOrEmail(
	ctx context.Context,
	opts GetUserByUsernameOrEmailOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "GetUserByUsernameOrEmail").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user by username or email...")

	switch opts.UsernameColumn {
	case database.AppUsernameColumnBoth:
		if utils.IsValidEmail(opts.UsernameOrEmail) {
			return s.GetUserByEmail(ctx, GetUserByEmailOptions{
				RequestID: opts.RequestID,
				AccountID: opts.AccountID,
				Email:     opts.UsernameOrEmail,
			})
		}
		if utils.IsValidSlug(opts.UsernameOrEmail) {
			return s.GetUserByUsername(ctx, GetUserByUsernameOptions{
				RequestID: opts.RequestID,
				AccountID: opts.AccountID,
				Username:  opts.UsernameOrEmail,
			})
		}
		logger.WarnContext(ctx, "Invalid username or email", "usernameOrEmail", opts.UsernameOrEmail)
		return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
	case database.AppUsernameColumnEmail:
		if !utils.IsValidEmail(opts.UsernameOrEmail) {
			logger.WarnContext(ctx, "Invalid email", "email", opts.UsernameOrEmail)
			return dtos.UserDTO{}, exceptions.NewValidationError("Invalid email")
		}
		return s.GetUserByEmail(ctx, GetUserByEmailOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			Email:     opts.UsernameOrEmail,
		})
	case database.AppUsernameColumnUsername:
		if !utils.IsValidSlug(opts.UsernameOrEmail) {
			logger.WarnContext(ctx, "Invalid username", "username", opts.UsernameOrEmail)
			return dtos.UserDTO{}, exceptions.NewValidationError("Invalid username")
		}
		return s.GetUserByUsername(ctx, GetUserByUsernameOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			Username:  opts.UsernameOrEmail,
		})
	default:
		logger.WarnContext(ctx, "Invalid username column", "usernameColumn", opts.UsernameColumn)
		return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
	}
}

type LoginUserOptions struct {
	RequestID       string
	AccountID       int32
	AccountUsername string
	AppClientID     string
	AppVersion      int32
	UsernameOrEmail string
	Password        string
}

func (s *Services) LoginUser(
	ctx context.Context,
	opts LoginUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "LoginUser").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Logging in user...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.AuthProviders, database.AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Invalid Provider", "Provider", AuthProviderUsernamePassword)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userDTO, serviceErr := s.GetUserByUsernameOrEmail(ctx, GetUserByUsernameOrEmailOptions{
		RequestID:       opts.RequestID,
		AccountID:       opts.AccountID,
		UsernameColumn:  appDTO.UsernameColumn,
		UsernameOrEmail: opts.UsernameOrEmail,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by username or email", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  appDTO.ID(),
		UserID: userDTO.ID(),
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app profile by app ID and user ID", "error", err)
			return dtos.AuthDTO{}, serviceErr
		}

		if err := s.database.CreateAppProfile(ctx, database.CreateAppProfileParams{
			AccountID: opts.AccountID,
			UserID:    userDTO.ID(),
			AppID:     appDTO.ID(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	}

	passwordVerified, err := utils.Argon2CompareHash(opts.Password, userDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !passwordVerified {
		logger.WarnContext(ctx, "Passwords do not match")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if !userDTO.EmailVerified() {
		logger.InfoContext(ctx, "User is not confirmed, sending new confirmation email")

		if serviceErr := s.sendUserConfirmationEmail(ctx, &userDTO, sendUserConfirmationEmailOptions{
			requestID:       opts.RequestID,
			accountID:       opts.AccountID,
			accountUsername: opts.AccountUsername,
			appVersion:      appDTO.Version(),
			appClientID:     appDTO.ClientID,
			appName:         appDTO.Name,
			// TODO: add from app type appConfirmationURI: appDTO.ConfirmationURI,
		}); serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
	}

	switch userDTO.TwoFactorType {
	case database.TwoFactorTypeEmail, database.TwoFactorTypeTotp:
		logger.WarnContext(ctx, "User has two-factor authentication enabled")
		twoFAToken, err := s.jwt.CreateUserPurposeToken(tokens.UserPurposeTokenOptions{
			TokenType:       tokens.PurposeTokenTypeTwoFA,
			AccountUsername: opts.AccountUsername,
			UserPublicID:    userDTO.PublicID,
			UserVersion:     userDTO.Version(),
			AppClientID:     appDTO.ClientID,
			AppVersion:      appDTO.Version(),
			Path:            paths.AppsBase + paths.UsersBase + paths.AuthLogin + paths.Auth2FA,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create two-factor authentication token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		signedTwoFAToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
			RequestID: opts.RequestID,
			Token:     twoFAToken,
			GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, logger, BuildGetEncryptedAccountJWKFnOptions{
				RequestID: opts.RequestID,
				KeyType:   database.TokenKeyType2faAuthentication,
				AccountID: opts.AccountID,
			}),
			GetDEKfn: s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
				requestID: opts.RequestID,
				accountID: opts.AccountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to sign two-factor authentication token", "serviceError", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}

		if userDTO.TwoFactorType == database.TwoFactorTypeEmail {
			code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
				RequestID: opts.RequestID,
				AccountID: opts.AccountID,
				UserID:    userDTO.ID(),
				TTL:       s.jwt.Get2FATTL(),
			})
			if err != nil {
				logger.ErrorContext(ctx, "Failed to add two-factor Code", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}

			if err := s.mail.PublishUser2FAEmail(ctx, mailer.User2FAEmailOptions{
				RequestID: opts.RequestID,
				AppName:   appDTO.Name,
				Email:     userDTO.Email,
				Code:      code,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to publish 2FA email", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}
		}

		return dtos.NewTempAuthDTO(
			signedTwoFAToken,
			"Please provide two factor Code",
			s.jwt.Get2FATTL(),
		), nil
	}

	return s.generateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		appDTO.DefaultScopes,
		opts.AccountUsername,
		"User logged in successfully",
	)
}

type verifyUserTotpOptions struct {
	requestID string
	userID    int32
	code      string
}

func (s *Services) verifyUserTotp(
	ctx context.Context,
	opts verifyUserTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, usersAuthLocation, "verifyUserTotp").With(
		"userId", opts.userID,
	)
	logger.InfoContext(ctx, "Verifying user TOTP...")

	verified, err := s.crypto.VerifyTotpCode(ctx, crypto.VerifyTotpCodeOptions{
		RequestID: opts.requestID,
		Code:      opts.code,
		OwnerID:   opts.userID,
		GetSecret: func(ownerID int32) (crypto.DEKCiphertext, *exceptions.ServiceError) {
			userTOTP, err := s.database.FindUserTotpByUserID(ctx, opts.userID)
			if err != nil {
				serviceErr := exceptions.FromDBError(err)
				if serviceErr.Code == exceptions.CodeNotFound {
					logger.WarnContext(ctx, "User TOTP not found", "error", err)
					return "", exceptions.NewForbiddenError()
				}

				logger.ErrorContext(ctx, "Failed to get user TOTP", "error", err)
				return "", serviceErr
			}

			return userTOTP.Secret, nil
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", err)
		return false, exceptions.NewServerError()
	}

	if !verified {
		logger.WarnContext(ctx, "Invalid TOTP Code")
		return false, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "User TOTP verified successfully")
	return true, nil
}

type verifierUserEmailCodeOptions struct {
	requestID string
	accountID int32
	userID    int32
	code      string
}

func (s *Services) verifyUserEmailCode(
	ctx context.Context,
	opts verifierUserEmailCodeOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, usersAuthLocation, "verifyUserEmailCode").With(
		"accountId", opts.accountID,
		"userId", opts.userID,
	)
	logger.InfoContext(ctx, "Verifying user email Code...")

	ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		UserID:    opts.userID,
		Code:      opts.code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify two factor Code", "error", err)
		return false, exceptions.NewServerError()
	}

	if !ok {
		logger.WarnContext(ctx, "Invalid two factor Code")
		return false, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "User two factor Code verified successfully")
	return true, nil
}

type TwoFactorLoginUserOptions struct {
	RequestID       string
	AccountID       int32
	AccountUsername string
	AppClientID     string
	AppVersion      int32
	UserPublicID    uuid.UUID
	UserVersion     int32
	Code            string
}

func (s *Services) TwoFactorLoginUser(
	ctx context.Context,
	opts TwoFactorLoginUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "TwoFactorLoginUser").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
		"userPublicId", opts.UserPublicID,
	)
	logger.InfoContext(ctx, "Two-factor login for user...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	userDTO, serviceErr := s.GetUserByPublicIDAndVersion(ctx, GetUserByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		PublicID:  opts.UserPublicID,
		Version:   opts.UserVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  appDTO.ID(),
		UserID: userDTO.ID(),
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	// Verify the two-factor Code based on the user's two-factor type
	var verified bool
	switch userDTO.TwoFactorType {
	case database.TwoFactorTypeTotp:
		verified, serviceErr = s.verifyUserTotp(ctx, verifyUserTotpOptions{
			requestID: opts.RequestID,
			userID:    userDTO.ID(),
			code:      opts.Code,
		})
	case database.TwoFactorTypeEmail:
		verified, serviceErr = s.verifyUserEmailCode(ctx, verifierUserEmailCodeOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			userID:    userDTO.ID(),
			code:      opts.Code,
		})
	default:
		logger.WarnContext(ctx, "Invalid two-factor type", "twoFactorType", userDTO.TwoFactorType)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}
	if !verified {
		logger.WarnContext(ctx, "Two-factor Code verification failed")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	return s.generateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		appDTO.DefaultScopes,
		opts.AccountUsername,
		"User two-factor login successful",
	)
}

type LogoutUserOptions struct {
	RequestID    string
	AccountID    int32
	AppClientID  string
	AppVersion   int32
	UserPublicID uuid.UUID
	UserVersion  int32
	Token        string
}

func (s *Services) LogoutUser(
	ctx context.Context,
	opts LogoutUserOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "LogoutUser").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
		"userPublicId", opts.UserPublicID,
		"userVersion", opts.UserVersion,
	)
	logger.InfoContext(ctx, "Logging out user...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return serviceErr
	}

	userClaims, appClaims, _, tokenID, exp, err := s.jwt.VerifyUserAuthToken(
		opts.Token,
		utils.SupportedCryptoSuiteEd25519,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   database.TokenKeyTypeRefresh,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return exceptions.NewUnauthorizedError()
	}
	if userClaims.UserID != opts.UserPublicID {
		logger.WarnContext(ctx, "Invalid user ID", "tokenUserId", userClaims.UserID, "userPublicId", opts.UserPublicID)
		return exceptions.NewUnauthorizedError()
	}
	if appClaims.ClientID != appDTO.ClientID {
		logger.WarnContext(ctx, "Invalid app client ID", "tokenAppClientId", appClaims.ClientID, "appClientId", opts.AppClientID)
		return exceptions.NewUnauthorizedError()
	}

	if _, serviceErr := s.GetUserByPublicIDAndVersion(ctx, GetUserByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		PublicID:  opts.UserPublicID,
		Version:   opts.UserVersion,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return serviceErr
	}

	blt, err := s.database.GetRevokedToken(ctx, tokenID)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch revoked token", "error", err)
			return exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is revoked", "revokedAt", blt.CreatedAt)
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.RevokeToken(ctx, database.RevokeTokenParams{
		TokenID:   tokenID,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to revoke token", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "User logged out successfully")
	return nil
}

type RefreshUserAccessOptions struct {
	RequestID       string
	AccountID       int32
	AppClientID     string
	AppVersion      int32
	AccountUsername string
	Token           string
}

func (s *Services) RefreshUserAccess(
	ctx context.Context,
	opts RefreshUserAccessOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "RefreshUserAccess").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Refreshing user access token...")

	userClaims, appClaims, scopes, tokenID, _, err := s.jwt.VerifyUserAuthToken(
		opts.Token,
		utils.SupportedCryptoSuiteEd25519,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   database.TokenKeyTypeRefresh,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.ClientID != opts.AppClientID {
		logger.WarnContext(ctx, "Invalid app client ID", "tokenAppClientId", appClaims.ClientID, "appClientId", opts.AppClientID)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	// Check if token is blacklisted
	blt, err := s.database.GetRevokedToken(ctx, tokenID)
	if err == nil {
		logger.WarnContext(ctx, "Token is revoked", "revokedAt", blt.CreatedAt)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	} else if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
		logger.ErrorContext(ctx, "Failed to check blacklisted token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	userDTO, serviceErr := s.GetUserByPublicIDAndVersion(ctx, GetUserByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		PublicID:  userClaims.UserID,
		Version:   userClaims.UserVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	userVersion := userDTO.Version()
	if userVersion != userClaims.UserVersion {
		logger.WarnContext(ctx, "User version mismatch", "claimsVersion", userClaims.UserVersion, "userVersion", userVersion)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		ClientID:  appClaims.ClientID,
		Version:   appClaims.Version,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  appDTO.ID(),
		UserID: userDTO.ID(),
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.generateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		scopes,
		opts.AccountUsername,
		"User access token refreshed successfully",
	)
}

type ForgotUserPasswordOptions struct {
	RequestID       string
	AccountID       int32
	AccountUsername string
	AppClientID     string
	AppVersion      int32
	Email           string
}

func (s *Services) ForgotUserPassword(
	ctx context.Context,
	opts ForgotUserPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ForgotUserPassword").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Forgout user password...")

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.AuthProviders, database.AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Username and password provider missing", "appProviders", appDTO.AuthProviders)
		return dtos.MessageDTO{}, exceptions.NewForbiddenError()
	}

	email := utils.Lowered(opts.Email)
	userDTO, serviceErr := s.GetUserByEmail(ctx, GetUserByEmailOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		Email:     email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.NewMessageDTO(forgotUserMessage), nil
		}

		logger.ErrorContext(ctx, "Failed to get user by email", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  appDTO.ID(),
		UserID: userDTO.ID(),
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.NewMessageDTO(forgotMessage), nil
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	resetToken, err := s.jwt.CreateUserPurposeToken(tokens.UserPurposeTokenOptions{
		TokenType:       tokens.PurposeTokenTypeReset,
		AccountUsername: opts.AccountUsername,
		UserPublicID:    userDTO.PublicID,
		UserVersion:     userDTO.Version(),
		AppClientID:     appDTO.ClientID,
		AppVersion:      appDTO.Version(),
		Path:            paths.AppsBase + paths.UsersBase + paths.AuthResetPassword,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create reset token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	signedResetToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token:     resetToken,
		GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, logger, BuildGetEncryptedAccountJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypePasswordReset,
			AccountID: opts.AccountID,
		}),
		GetDEKfn: s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign reset token", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if err := s.mail.PublishUserResetEmail(ctx, mailer.UserResetEmailOptions{
		RequestID:  opts.RequestID,
		AppName:    appDTO.Name,
		Email:      userDTO.Email,
		ResetToken: signedResetToken,
		// TODO: add from app type ResetURI: appDTO.ResetURI,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish reset email", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	return dtos.NewMessageDTO(forgotUserMessage), nil
}

type ResetUserPasswordOptions struct {
	RequestID   string
	AccountID   int32
	AppClientID string
	AppVersion  int32
	Password    string
	ResetToken  string
}

func (s *Services) ResetUserPassword(
	ctx context.Context,
	opts ResetUserPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ResetUserPassword").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Forgout user password...")

	userClaims, appClaims, _, err := s.jwt.VerifyUserPurposeToken(
		opts.ResetToken,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   database.TokenKeyTypePasswordReset,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify refresh token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.ClientID != opts.AppClientID {
		logger.WarnContext(ctx, "Invalid app client ID", "tokenAppClientId", appClaims.ClientID, "appClientId", opts.AppClientID)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	appDTO, serviceErr := s.GetAppByClientIDVersionAndAccountID(ctx, GetAppByClientIDVersionAndAccountIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		ClientID:  opts.AppClientID,
		Version:   opts.AppVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.AuthProviders, database.AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Username and password provider missing", "appProviders", appDTO.AuthProviders)
		return dtos.MessageDTO{}, exceptions.NewForbiddenError()
	}

	userDTO, serviceErr := s.GetUserByPublicIDAndVersion(ctx, GetUserByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		PublicID:  userClaims.UserID,
		Version:   userClaims.UserVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	userVersion := userDTO.Version()
	if userVersion != userClaims.UserVersion {
		logger.WarnContext(ctx, "User and claims versions do not match",
			"userVersion", userVersion,
			"claimsVersion", userClaims.UserVersion,
		)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	if _, err := s.database.FindAppProfileIDByAppIDAndUserID(ctx, database.FindAppProfileIDByAppIDAndUserIDParams{
		AppID:  appDTO.ID(),
		UserID: userDTO.ID(),
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found", "serviceError", serviceErr)
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	var password pgtype.Text
	hashedPassword, err := utils.Argon2HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	_, err = s.database.FindUserAuthProviderByUserIDAndProvider(ctx, database.FindUserAuthProviderByUserIDAndProviderParams{
		UserID:   userDTO.ID(),
		Provider: database.AuthProviderUsernamePassword,
	})
	if err == nil {
		if _, err := s.database.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
			ID:       userDTO.ID(),
			Password: password,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update user password", "error", err)
			return dtos.MessageDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "User password reset successfully")
		return dtos.NewMessageDTO(resetUserMessage), nil
	}
	if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
		logger.ErrorContext(ctx, "Failed to find user auth provider", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.MessageDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	if _, err = qrs.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
		ID:       userDTO.ID(),
		Password: password,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update user password", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.MessageDTO{}, serviceErr
	}

	if err = qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    userDTO.ID(),
		Provider:  database.AuthProviderUsernamePassword,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create username and password user auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.MessageDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "User password reset successfully")
	return dtos.NewMessageDTO(resetUserMessage), nil
}
