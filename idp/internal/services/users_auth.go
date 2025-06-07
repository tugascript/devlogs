// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"log/slog"
	"reflect"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
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

type ProcessUserAuthHeaderOptions struct {
	RequestID  string
	AuthHeader string
	Name       AppKeyName
}

func (s *Services) ProcessUserAuthHeader(
	ctx context.Context,
	opts ProcessUserAuthHeaderOptions,
) (tokens.UserClaims, tokens.AppClaims, []string, *exceptions.ServiceError) {
	if opts.AuthHeader == "" {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	parts := strings.Split(opts.AuthHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	userClaims, appClaims, scope, _, _, err := s.jwt.VerifyUserToken(
		s.GetAccountKeyFn(ctx, GetAccountKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      opts.Name,
		}),
		parts[1],
	)
	if err != nil {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return userClaims, appClaims, strings.Split(scope, " "), nil
}

type sendUserConfirmationEmailOptions struct {
	requestID          string
	accountID          int32
	accountUsername    string
	appID              int32
	appClientID        string
	appName            string
	appConfirmationURI string
}

func (s *Services) sendUserConfirmationEmail(
	ctx context.Context,
	logger *slog.Logger,
	userDTO *dtos.UserDTO,
	profileDTO *dtos.AppProfileDTO,
	opts sendUserConfirmationEmailOptions,
) *exceptions.ServiceError {
	appKeyDTO, serviceErr := s.GetOrCreateAccountKey(ctx, GetOrCreateAccountKeyOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		Name:      AppKeyNameConfirm,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app key", "error", serviceErr)
		return serviceErr
	}

	token, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     appKeyDTO.JWTCryptoSuite(),
		Type:            tokens.TokenTypeConfirmation,
		PrivateKey:      appKeyDTO.PrivateKey(),
		KID:             appKeyDTO.PublicKID(),
		AccountUsername: opts.accountUsername,
		UserID:          userDTO.ID,
		UserVersion:     userDTO.Version(),
		UserEmail:       userDTO.Email,
		ProfileRoles:    profileDTO.Roles,
		Scopes:          []string{tokens.UserScopeConfirmation},
		AppID:           opts.appID,
		AppClientID:     opts.appClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user token", "error", err)
		return exceptions.NewServerError()
	}

	if err := s.mail.PublishUserConfirmationEmail(ctx, mailer.UserConfirmationEmailOptions{
		RequestID:         opts.requestID,
		AppName:           opts.appName,
		Email:             userDTO.Email,
		ConfirmationURI:   opts.appConfirmationURI,
		ConfirmationToken: token,
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
	AppID           int32
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
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Registering user...")

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.Providers, AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Invalid Provider")
		return dtos.MessageDTO{}, exceptions.NewForbiddenError()
	}

	userDTO, profileDTO, serviceErr := s.CreateAppUser(ctx, CreateAppUserOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
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

	if serviceErr := s.sendUserConfirmationEmail(ctx, logger, &userDTO, &profileDTO, sendUserConfirmationEmailOptions{
		requestID:          opts.RequestID,
		accountID:          opts.AccountID,
		accountUsername:    opts.AccountUsername,
		appID:              opts.AppID,
		appClientID:        appDTO.ClientID,
		appName:            appDTO.Name,
		appConfirmationURI: appDTO.ConfirmationURI,
	}); serviceErr != nil {
		return dtos.MessageDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Registered user successfully")
	return dtos.NewMessageDTO("User registered successfully. Confirmation email hasd been sent"), nil
}

func (s *Services) GenerateFullUserAuthDTO(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountID int32,
	userDTO *dtos.UserDTO,
	appDTO *dtos.AppDTO,
	appProfileDTO *dtos.AppProfileDTO,
	accountUsername,
	logSuccessMessage string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	accountKeyDTOs, serviceErr := s.GetOrCreateMultipleAccountKeys(ctx, GetOrCreateMultipleAccountKeysOptions{
		RequestID: requestID,
		AccountID: accountID,
		Names:     []AppKeyName{AppKeyNameAccess, AppKeyNameRefresh},
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app keys", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	keyDTOsMap := make(map[AppKeyName]dtos.AccountKeyDTO)
	for _, key := range accountKeyDTOs {
		keyDTOsMap[AppKeyName(key.Name())] = key
	}

	accessTokenKey := keyDTOsMap[AppKeyNameAccess]
	accessToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     accessTokenKey.JWTCryptoSuite(),
		Type:            tokens.TokenTypeAccess,
		PrivateKey:      accessTokenKey.PrivateKey(),
		KID:             accessTokenKey.PublicKID(),
		AccountUsername: accountUsername,
		UserID:          userDTO.ID,
		UserVersion:     userDTO.Version(),
		UserEmail:       userDTO.Email,
		Scopes:          appDTO.DefaultScopes,
		ProfileRoles:    appProfileDTO.Roles,
		AppID:           appDTO.ID(),
		AppClientID:     appDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	refreshTokenKey := keyDTOsMap[AppKeyNameRefresh]
	refreshToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     refreshTokenKey.JWTCryptoSuite(),
		Type:            tokens.TokenTypeRefresh,
		PrivateKey:      refreshTokenKey.PrivateKey(),
		KID:             refreshTokenKey.PublicKID(),
		AccountUsername: accountUsername,
		UserID:          userDTO.ID,
		UserVersion:     userDTO.Version(),
		UserEmail:       userDTO.Email,
		Scopes:          []string{tokens.UserScopeRefresh},
		ProfileRoles:    appProfileDTO.Roles,
		AppID:           appDTO.ID(),
		AppClientID:     appDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, logSuccessMessage)
	return dtos.NewFullAuthDTO(accessToken, refreshToken, s.jwt.GetAccessTTL()), nil
}

type ConfirmAuthUserOptions struct {
	RequestID         string
	AccountID         int32
	AccountUsername   string
	AppID             int32
	ConfirmationToken string
}

func (s *Services) ConfirmAuthUser(
	ctx context.Context,
	opts ConfirmAuthUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ConfirmAuthUser").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Confirming user...")

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.Providers, AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Invalid Provider", "Provider", AuthProviderUsernamePassword)
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}

	userClaims, appClaims, _, _, _, err := s.jwt.VerifyUserToken(
		s.GetAccountKeyFn(ctx, GetAccountKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameConfirm,
		}),
		opts.ConfirmationToken,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.AppID != opts.AppID {
		logger.WarnContext(ctx, "Invalid app ID", "tokenAppId", appClaims.AppID, "appId", opts.AppID)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userDTO, profileDTO, serviceErr := s.ConfirmAppUser(ctx, ConfirmAppUserOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		UserID:    userClaims.UserID,
		Version:   userClaims.UserVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to confirm user", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.GenerateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		&profileDTO,
		opts.AccountUsername,
		"User confirmed successfully",
	)
}

type GetUserByUsernameOrEmailOptions struct {
	RequestID       string
	AccountID       int32
	UsernameColumn  string
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
	case UsernameColumnBoth:
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
	case UsernameColumnEmail:
		if !utils.IsValidEmail(opts.UsernameOrEmail) {
			logger.WarnContext(ctx, "Invalid email", "email", opts.UsernameOrEmail)
			return dtos.UserDTO{}, exceptions.NewValidationError("Invalid email")
		}
		return s.GetUserByEmail(ctx, GetUserByEmailOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			Email:     opts.UsernameOrEmail,
		})
	case UsernameColumnUsername:
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
	AppID           int32
	UsernameOrEmail string
	Password        string
}

func (s *Services) LoginUser(
	ctx context.Context,
	opts LoginUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "LoginUser").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Logging in user...")

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.Providers, AuthProviderUsernamePassword) {
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

	profileDTO, serviceErr := s.GetOrCreateAppProfile(ctx, GetOrCreateAppProfileOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     appDTO.ID(),
		UserID:    userDTO.ID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app profile", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	passwordVerified, err := utils.CompareHash(opts.Password, userDTO.Password())
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

		if serviceErr := s.sendUserConfirmationEmail(ctx, logger, &userDTO, &profileDTO, sendUserConfirmationEmailOptions{
			requestID:          opts.RequestID,
			accountID:          opts.AccountID,
			accountUsername:    opts.AccountUsername,
			appID:              appDTO.ID(),
			appClientID:        appDTO.ClientID,
			appName:            appDTO.Name,
			appConfirmationURI: appDTO.ConfirmationURI,
		}); serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
	}

	switch userDTO.TwoFactorType {
	case TwoFactorEmail, TwoFactorTotp:
		logger.WarnContext(ctx, "User has two-factor authentication enabled")
		appKeyDTO, serviceErr := s.GetOrCreateAccountKey(ctx, GetOrCreateAccountKeyOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			Name:      AppKeyName2FA,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get or create app key", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
		twoFAToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
			CryptoSuite:     appKeyDTO.JWTCryptoSuite(),
			Type:            tokens.TokenTypeTwoFA,
			PrivateKey:      appKeyDTO.PrivateKey(),
			KID:             appKeyDTO.PublicKID(),
			AccountUsername: opts.AccountUsername,
			UserID:          int32(userDTO.ID),
			UserVersion:     int32(userDTO.Version()),
			UserEmail:       userDTO.Email,
			Scopes:          []string{tokens.UserScope2FA},
			AppID:           int32(appDTO.ID()),
			AppClientID:     appDTO.ClientID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create two-factor authentication token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		if userDTO.TwoFactorType == TwoFactorEmail {
			code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
				RequestID: opts.RequestID,
				AccountID: opts.AccountID,
				UserID:    userDTO.ID,
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
			twoFAToken,
			"Please provide two factor Code",
			s.jwt.Get2FATTL(),
		), nil
	}

	return s.GenerateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		&profileDTO,
		opts.AccountUsername,
		"User logged in successfully",
	)
}

type verifyUserTotpOptions struct {
	requestID string
	userID    int32
	code      string
	dek       string
}

func (s *Services) verifyUserTotp(
	ctx context.Context,
	opts verifyUserTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, usersAuthLocation, "verifyUserTotp").With(
		"userId", opts.userID,
	)
	logger.InfoContext(ctx, "Verifying user TOTP...")

	userTOTP, err := s.database.FindUserTotpByUserID(ctx, opts.userID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User TOTP not found", "error", err)
			return false, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get user TOTP", "error", err)
		return false, serviceErr
	}

	ok, newDEK, err := s.encrypt.VerifyTotpCode(ctx, encryption.VerifyAccountTotpCodeOptions{
		RequestID:       opts.requestID,
		EncryptedSecret: userTOTP.Secret,
		StoredDEK:       opts.dek,
		Code:            opts.code,
		TotpType:        encryption.TotpTypeUser,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", err)
		return false, exceptions.NewServerError()
	}

	if !ok {
		logger.WarnContext(ctx, "Invalid TOTP Code")
		return false, exceptions.NewUnauthorizedError()
	}

	if newDEK != "" {
		if err := s.database.UpdateUserDEK(ctx, database.UpdateUserDEKParams{
			Dek: newDEK,
			ID:  userTOTP.UserID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update user TOTP", "error", err)
			return false, exceptions.NewServerError()
		}
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
	AppID           int32
	UserID          int32
	Version         int32
	Code            string
}

func (s *Services) TwoFactorLoginUser(
	ctx context.Context,
	opts TwoFactorLoginUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "TwoFactorLoginUser").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Two-factor login for user...")

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		UserID:    opts.UserID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	profileDTO, serviceErr := s.GetAppProfile(ctx, GetAppProfileOptions{
		RequestID: opts.RequestID,
		AppID:     appDTO.ID(),
		UserID:    opts.UserID,
	})
	if serviceErr != nil {
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
	case TwoFactorTotp:
		verified, serviceErr = s.verifyUserTotp(ctx, verifyUserTotpOptions{
			requestID: opts.RequestID,
			userID:    opts.UserID,
			code:      opts.Code,
			dek:       userDTO.DEK(),
		})
	case TwoFactorEmail:
		verified, serviceErr = s.verifyUserEmailCode(ctx, verifierUserEmailCodeOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			userID:    opts.UserID,
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

	return s.GenerateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		&profileDTO,
		opts.AccountUsername,
		"User two-factor login successful",
	)
}

type LogoutUserOptions struct {
	RequestID string
	AccountID int32
	AppID     int32
	UserID    int32
	Token     string
}

func (s *Services) LogoutUser(
	ctx context.Context,
	opts LogoutUserOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "LogoutUser").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Logging out user...")

	userClaims, appClaims, scope, tokenID, exp, err := s.jwt.VerifyUserToken(
		s.GetAccountKeyFn(ctx, GetAccountKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameRefresh,
		}),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return exceptions.NewUnauthorizedError()
	}
	if strings.Contains(scope, tokens.UserScopeRefresh) {
		logger.WarnContext(ctx, "Invalid scope", "scope", scope)
		return exceptions.NewUnauthorizedError()
	}
	if userClaims.UserID != opts.UserID {
		logger.WarnContext(ctx, "Invalid user ID", "tokenUserId", userClaims.UserID, "userId", opts.UserID)
		return exceptions.NewUnauthorizedError()
	}
	if appClaims.AppID != opts.AppID {
		logger.WarnContext(ctx, "Invalid app ID", "tokenAppId", appClaims.AppID, "appId", opts.AppID)
		return exceptions.NewUnauthorizedError()
	}

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    opts.UserID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return serviceErr
	}

	if userDTO.Version() != userClaims.UserVersion {
		logger.WarnContext(ctx, "User version mismatch", "tokenVersion", userClaims.UserVersion, "userVersion", userDTO.Version())
		return exceptions.NewUnauthorizedError()
	}

	blt, err := s.database.GetBlacklistedToken(ctx, tokenID)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch blacklisted token", "error", err)
			return exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is blacklisted", "blacklistedAt", blt.CreatedAt)
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.BlacklistToken(ctx, database.BlacklistTokenParams{
		ID:        tokenID,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to blacklist token", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "User logged out successfully")
	return nil
}

type RefreshUserAccessOptions struct {
	RequestID       string
	AccountID       int32
	AppID           int32
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

	userClaims, appClaims, _, tokenID, _, err := s.jwt.VerifyUserToken(
		s.GetAccountKeyFn(ctx, GetAccountKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameRefresh,
		}),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.AppID != opts.AppID {
		logger.WarnContext(ctx, "Invalid app ID", "tokenAppId", appClaims.AppID, "appId", opts.AppID)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	// Check if token is blacklisted
	blt, err := s.database.GetBlacklistedToken(ctx, tokenID)
	if err == nil {
		logger.WarnContext(ctx, "Token is blacklisted", "blacklistedAt", blt.CreatedAt)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	} else if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
		logger.ErrorContext(ctx, "Failed to check blacklisted token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		UserID:    userClaims.UserID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	userVersion := userDTO.Version()
	if userVersion != userClaims.UserVersion {
		logger.WarnContext(ctx, "User version mismatch", "claimsVersion", userClaims.UserVersion, "userVersion", userVersion)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     appClaims.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	appProfileDTO, serviceErr := s.GetAppProfile(ctx, GetAppProfileOptions{
		RequestID: opts.RequestID,
		AppID:     appClaims.AppID,
		UserID:    userClaims.UserID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.GenerateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		opts.AccountID,
		&userDTO,
		&appDTO,
		&appProfileDTO,
		opts.AccountUsername,
		"User access token refreshed successfully",
	)
}

type ForgoutUserPasswordOptions struct {
	RequestID       string
	AccountID       int32
	AccountUsername string
	AppID           int32
	AppClientID     string
	Email           string
}

func (s *Services) ForgoutUserPassword(
	ctx context.Context,
	opts ForgoutUserPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ForgoutUserPassword").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Forgout user password...")

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.Providers, AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Username and password provider missing", "appProviders", appDTO.Providers)
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

	profileDTO, serviceErr := s.GetAppProfile(ctx, GetAppProfileOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		UserID:    userDTO.ID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.NewMessageDTO(forgotMessage), nil
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	appKeyDTO, serviceErr := s.GetOrCreateAccountKey(ctx, GetOrCreateAccountKeyOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		Name:      AppKeyNameReset,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app key", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	resetToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     appKeyDTO.JWTCryptoSuite(),
		Type:            tokens.TokenTypeConfirmation,
		PrivateKey:      appKeyDTO.PrivateKey(),
		KID:             appKeyDTO.PublicKID(),
		AccountUsername: opts.AccountUsername,
		UserID:          userDTO.ID,
		UserVersion:     userDTO.Version(),
		UserEmail:       userDTO.Email,
		ProfileRoles:    profileDTO.Roles,
		Scopes:          []string{tokens.UserScopeReset},
		AppID:           opts.AppID,
		AppClientID:     opts.AppClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create reset token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := s.mail.PublishUserResetEmail(ctx, mailer.UserResetEmailOptions{
		RequestID:  opts.RequestID,
		AppName:    appDTO.Name,
		Email:      userDTO.Email,
		ResetToken: resetToken,
		ResetURI:   appDTO.ResetURI,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish reset email", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	return dtos.NewMessageDTO(forgotUserMessage), nil
}

type ResetUserPasswordOptions struct {
	RequestID  string
	AccountID  int32
	AppID      int32
	Password   string
	ResetToken string
}

func (s *Services) ResetUserPassword(
	ctx context.Context,
	opts ResetUserPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ResetUserPassword").With(
		"accountId", opts.AccountID,
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Forgout user password...")

	userClaims, appClaims, _, _, _, err := s.jwt.VerifyUserToken(
		s.GetAccountKeyFn(ctx, GetAccountKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameReset,
		}),
		opts.ResetToken,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify refresh token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.AppID != opts.AppID {
		logger.WarnContext(ctx, "Invalid app ID", "tokenAppId", appClaims.AppID, "appId", opts.AppID)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if !slices.Contains(appDTO.Providers, AuthProviderUsernamePassword) {
		logger.WarnContext(ctx, "Username and password provider missing", "appProviders", appDTO.Providers)
		return dtos.MessageDTO{}, exceptions.NewForbiddenError()
	}

	userDTO, serviceErr := s.GetUserByID(ctx, GetUserByIDOptions{
		RequestID: opts.RequestID,
		UserID:    userClaims.UserID,
		AccountID: opts.AccountID,
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

	if _, serviceErr := s.GetAppProfile(ctx, GetAppProfileOptions{
		RequestID: opts.RequestID,
		AppID:     appClaims.AppID,
		UserID:    userClaims.UserID,
	}); serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found", "serviceError", serviceErr)
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app profile", "serviceError", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	var password pgtype.Text
	hashedPassword, err := utils.HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	_, err = s.database.FindUserAuthProviderByUserIDAndProvider(ctx, database.FindUserAuthProviderByUserIDAndProviderParams{
		UserID:   userClaims.UserID,
		Provider: AuthProviderUsernamePassword,
	})
	if err == nil {
		if _, err := s.database.UpdateUserPassword(ctx, database.UpdateUserPasswordParams{
			ID:       userDTO.ID,
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
		ID:       userDTO.ID,
		Password: password,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update user password", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.MessageDTO{}, serviceErr
	}

	if err = qrs.CreateUserAuthProvider(ctx, database.CreateUserAuthProviderParams{
		AccountID: opts.AccountID,
		UserID:    userClaims.UserID,
		Provider:  AuthProviderUsernamePassword,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create username and password user auth provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.MessageDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "User password reset successfully")
	return dtos.NewMessageDTO(resetUserMessage), nil
}
