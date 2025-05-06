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

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const usersAuthLocation string = "users_auth"

type sendUserConfirmationEmailOptions struct {
	requestID          string
	accountID          int32
	accountUsername    string
	appID              int32
	appClientID        string
	appName            string
	appConfirmationURI string
	appDEK             string
	appJwtCryptoSuite  string
}

func (s *Services) sendUserConfirmationEmail(
	ctx context.Context,
	logger *slog.Logger,
	userDTO *dtos.UserDTO,
	opts sendUserConfirmationEmailOptions,
) *exceptions.ServiceError {
	cryptoSuite, serviceErr := dtos.GetJwtCryptoSuite(opts.appJwtCryptoSuite)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get JWT crypto suite", "error", serviceErr)
		return serviceErr
	}

	appKeyDTO, serviceErr := s.GetOrCreateAppKey(ctx, GetOrCreateAppKeyOptions{
		RequestID:         opts.requestID,
		AppID:             opts.appID,
		AppDEK:            opts.appDEK,
		AppJwtCryptoSuite: cryptoSuite,
		AccountID:         opts.accountID,
		Name:              AppKeyNameConfirm,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app key", "error", serviceErr)
		return serviceErr
	}

	token, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     cryptoSuite,
		Type:            tokens.TokenTypeConfirmation,
		PrivateKey:      appKeyDTO.PrivateKey(),
		KID:             appKeyDTO.PublicKID(),
		AccountUsername: opts.accountUsername,
		UserID:          int32(userDTO.ID),
		UserVersion:     int32(userDTO.Version()),
		UserEmail:       userDTO.Email,
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
	RequestID          string
	AccountID          int32
	AccountUsername    string
	AppID              int32
	AppName            string
	AppClientID        string
	AppDEK             string
	AppJwtCryptoSuite  string
	AppConfirmationURI string
	Email              string
	Username           string
	Password           string
	AllowedProviders   []string
	UserData           reflect.Value
	AppData            reflect.Value
	AppDataMap         map[string]any
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

	userDTO, serviceErr := s.CreateAppUser(ctx, CreateAppUserOptions{
		RequestID:        opts.RequestID,
		AccountID:        opts.AccountID,
		AppID:            opts.AppID,
		Email:            opts.Email,
		Username:         opts.Username,
		Password:         opts.Password,
		Provider:         AuthProviderUsernamePassword,
		AllowedProviders: opts.AllowedProviders,
		UserData:         opts.UserData,
		AppData:          opts.AppData,
		AppDataMap:       opts.AppDataMap,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to register user", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if serviceErr := s.sendUserConfirmationEmail(ctx, logger, &userDTO, sendUserConfirmationEmailOptions{
		requestID:          opts.RequestID,
		accountID:          opts.AccountID,
		accountUsername:    opts.AccountUsername,
		appID:              opts.AppID,
		appClientID:        opts.AppClientID,
		appName:            opts.AppName,
		appConfirmationURI: opts.AppConfirmationURI,
		appDEK:             opts.AppDEK,
		appJwtCryptoSuite:  opts.AppJwtCryptoSuite,
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
	userDTO *dtos.UserDTO,
	appDTO *dtos.AppDTO,
	appProfileDTO *dtos.AppProfileDTO,
	accountUsername,
	logSuccessMessage string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	appKeysDTO, serviceErr := s.GetOrCreateAppKeys(ctx, GetOrCreateAppKeysOptions{
		RequestID: requestID,
		AppID:     int32(appDTO.ID()),
		AppDEK:    appDTO.DEK(),
		AccountID: int32(appDTO.AccountID()),
		AppKeyParams: []AppKeyParam{
			{
				Name:           AppKeyNameAccess,
				JwtCryptoSuite: getCryptoSuite(true, appDTO.JwtCryptoSuite),
			},
			{
				Name:           AppKeyNameRefresh,
				JwtCryptoSuite: getCryptoSuite(false, appDTO.JwtCryptoSuite),
			},
		},
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app keys", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accessTokenKey := appKeysDTO[AppKeyNameAccess]
	accessToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     accessTokenKey.JWTCryptoSuite(),
		Type:            tokens.TokenTypeAccess,
		PrivateKey:      accessTokenKey.PrivateKey(),
		KID:             accessTokenKey.PublicKID(),
		AccountUsername: accountUsername,
		UserID:          int32(userDTO.ID),
		UserVersion:     int32(userDTO.Version()),
		UserEmail:       userDTO.Email,
		AppProfileRoles: appProfileDTO.UserRoles(),
		AppID:           int32(appDTO.ID()),
		AppClientID:     appDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	refreshTokenKey := appKeysDTO[AppKeyNameRefresh]
	refreshToken, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     refreshTokenKey.JWTCryptoSuite(),
		Type:            tokens.TokenTypeRefresh,
		PrivateKey:      refreshTokenKey.PrivateKey(),
		KID:             refreshTokenKey.PublicKID(),
		AccountUsername: accountUsername,
		UserID:          int32(userDTO.ID),
		UserVersion:     int32(userDTO.Version()),
		UserEmail:       userDTO.Email,
		AppID:           int32(appDTO.ID()),
		AppClientID:     appDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, logSuccessMessage)
	return dtos.NewFullAuthDTO(accessToken, refreshToken, s.jwt.GetAccessTTL()), nil
}

type ConfirmAppUserOptions struct {
	RequestID         string
	AccountID         int32
	AccountUsername   string
	AppID             int32
	ConfirmationToken string
}

func (s *Services) ConfirmAppUser(
	ctx context.Context,
	opts ConfirmAppUserOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "ConfirmUser").With(
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
		logger.WarnContext(ctx, "Invalid provider", "provider", AuthProviderUsernamePassword)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userClaims, appClaims, _, _, err := s.jwt.VerifyUserToken(
		s.GetAppKeyFn(ctx, GetAppKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameConfirm,
			AppID:     int32(appDTO.ID()),
		}),
		opts.ConfirmationToken,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if appClaims.ID != opts.AppID {
		logger.WarnContext(ctx, "Invalid app ID", "tokenAppId", appClaims.ID, "appId", opts.AppID)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userDTO, serviceErr := s.ConfirmUser(ctx, ConfirmUserOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		UserID:    userClaims.ID,
		Version:   userClaims.Version,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to confirm user", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	profileDTO, serviceErr := s.GetAppProfileByIDs(ctx, GetAppProfileByIDsOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		UserID:    int32(userDTO.ID),
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
		&userDTO,
		&appDTO,
		&profileDTO,
		opts.AccountUsername,
		"User confirmed successfully",
	)
}

type getUserByUsernameOrEmailOptions struct {
	requestID       string
	accountID       int32
	usernameColumn  string
	usernameOrEmail string
}

func (s *Services) getUserByUsernameOrEmail(
	ctx context.Context,
	opts getUserByUsernameOrEmailOptions,
) (dtos.UserDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, usersAuthLocation, "GetUserByUsernameOrEmail").With(
		"accountId", opts.accountID,
	)
	logger.InfoContext(ctx, "Getting user by username or email...")

	switch opts.usernameColumn {
	case UsernameColumnBoth:
		if utils.IsValidEmail(opts.usernameOrEmail) {
			return s.GetUserByEmail(ctx, GetUserByEmailOptions{
				RequestID: opts.requestID,
				AccountID: opts.accountID,
				Email:     opts.usernameOrEmail,
			})
		}
		if utils.IsValidSlug(opts.usernameOrEmail) {
			return s.GetUserByUsername(ctx, GetUserByUsernameOptions{
				RequestID: opts.requestID,
				AccountID: opts.accountID,
				Username:  opts.usernameOrEmail,
			})
		}
		logger.WarnContext(ctx, "Invalid username or email", "usernameOrEmail", opts.usernameOrEmail)
		return dtos.UserDTO{}, exceptions.NewUnauthorizedError()
	case UsernameColumnEmail:
		if !utils.IsValidEmail(opts.usernameOrEmail) {
			logger.WarnContext(ctx, "Invalid email", "email", opts.usernameOrEmail)
			return dtos.UserDTO{}, exceptions.NewValidationError("Invalid email")
		}
		return s.GetUserByEmail(ctx, GetUserByEmailOptions{
			RequestID: opts.requestID,
			AccountID: opts.accountID,
			Email:     opts.usernameOrEmail,
		})
	case UsernameColumnUsername:
		if !utils.IsValidSlug(opts.usernameOrEmail) {
			logger.WarnContext(ctx, "Invalid username", "username", opts.usernameOrEmail)
			return dtos.UserDTO{}, exceptions.NewValidationError("Invalid username")
		}
		return s.GetUserByUsername(ctx, GetUserByUsernameOptions{
			RequestID: opts.requestID,
			AccountID: opts.accountID,
			Username:  opts.usernameOrEmail,
		})
	default:
		logger.WarnContext(ctx, "Invalid username column", "usernameColumn", opts.usernameColumn)
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
		logger.WarnContext(ctx, "Invalid provider", "provider", AuthProviderUsernamePassword)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	userDTO, serviceErr := s.getUserByUsernameOrEmail(ctx, getUserByUsernameOrEmailOptions{
		requestID:       opts.RequestID,
		accountID:       opts.AccountID,
		usernameColumn:  appDTO.UsernameColumn,
		usernameOrEmail: opts.UsernameOrEmail,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "User not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
		if serviceErr.Code == exceptions.CodeValidation {
			logger.WarnContext(ctx, "Invalid username or email", "usernameOrEmail", opts.UsernameOrEmail)
			return dtos.AuthDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get user by username or email", "error", serviceErr)
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

	if !userDTO.IsConfirmed() {
		logger.InfoContext(ctx, "User is not confirmed, sending new confirmation email")

		if serviceErr := s.sendUserConfirmationEmail(ctx, logger, &userDTO, sendUserConfirmationEmailOptions{
			requestID:          opts.RequestID,
			accountID:          opts.AccountID,
			accountUsername:    opts.AccountUsername,
			appID:              int32(appDTO.ID()),
			appClientID:        appDTO.ClientID,
			appName:            appDTO.Name,
			appConfirmationURI: appDTO.ConfirmationURI,
			appDEK:             appDTO.DEK(),
			appJwtCryptoSuite:  string(appDTO.JwtCryptoSuite),
		}); serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
	}

	switch userDTO.TwoFactorType {
	case TwoFactorEmail, TwoFactorTotp:
		logger.WarnContext(ctx, "User has two-factor authentication enabled")
		appKeyDTO, serviceErr := s.GetOrCreateAppKey(ctx, GetOrCreateAppKeyOptions{
			RequestID:         opts.RequestID,
			AppID:             opts.AppID,
			AppDEK:            appDTO.DEK(),
			AppJwtCryptoSuite: appDTO.JwtCryptoSuite,
			AccountID:         opts.AccountID,
			Name:              AppKeyNameAccess,
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
				AccountID: int(opts.AccountID),
				UserID:    userDTO.ID,
				TTL:       s.jwt.Get2FATTL(),
			})
			if err != nil {
				logger.ErrorContext(ctx, "Failed to add two-factor code", "error", err)
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
			"Please provide two factor code",
			s.jwt.Get2FATTL(),
		), nil
	}

	profileDTO, serviceErr := s.GetAppProfileByIDs(ctx, GetAppProfileByIDsOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		UserID:    int32(userDTO.ID),
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
		&userDTO,
		&appDTO,
		&profileDTO,
		opts.AccountUsername,
		"User logged in successfully",
	)
}

type VerifyUserTotpOptions struct {
	RequestID string
	UserID    int32
	Code      string
	DEK       string
}

func (s *Services) VerifyUserTotp(
	ctx context.Context,
	opts VerifyUserTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "VerifyUserTotp").With(
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Verifying user TOTP...")

	userTOTP, err := s.database.FindUserTotpByUserID(ctx, opts.UserID)
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
		RequestID:       opts.RequestID,
		EncryptedSecret: userTOTP.Secret,
		StoredDEK:       opts.DEK,
		Code:            opts.Code,
		TotpType:        encryption.TotpTypeUser,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", err)
		return false, exceptions.NewServerError()
	}

	if !ok {
		logger.WarnContext(ctx, "Invalid TOTP code")
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

type VerifierUserEmailCodeOptions struct {
	RequestID string
	AccountID int
	UserID    int
	Code      string
}

func (s *Services) VerifyUserEmailCode(
	ctx context.Context,
	opts VerifierUserEmailCodeOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, usersAuthLocation, "VerifyUserEmailCode").With(
		"accountId", opts.AccountID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Verifying user email code...")

	ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		UserID:    opts.UserID,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify two factor code", "error", err)
		return false, exceptions.NewServerError()
	}

	if !ok {
		logger.WarnContext(ctx, "Invalid two factor code")
		return false, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "User two factor code verified successfully")
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
	TwoFactorToken  string
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
		logger.ErrorContext(ctx, "Failed to get user by ID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	// Verify the two-factor code based on the user's two-factor type
	var verified bool
	switch userDTO.TwoFactorType {
	case TwoFactorTotp:
		verified, serviceErr = s.VerifyUserTotp(ctx, VerifyUserTotpOptions{
			RequestID: opts.RequestID,
			UserID:    opts.UserID,
			Code:      opts.Code,
			DEK:       userDTO.DEK(),
		})
	case TwoFactorEmail:
		verified, serviceErr = s.VerifyUserEmailCode(ctx, VerifierUserEmailCodeOptions{
			RequestID: opts.RequestID,
			AccountID: int(opts.AccountID),
			UserID:    int(opts.UserID),
			Code:      opts.Code,
		})
	default:
		logger.WarnContext(ctx, "Invalid two-factor type", "twoFactorType", userDTO.TwoFactorType)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}
	if !verified {
		logger.WarnContext(ctx, "Two-factor code verification failed")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	profileDTO, serviceErr := s.GetAppProfileByIDs(ctx, GetAppProfileByIDsOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		UserID:    opts.UserID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app profile", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.GenerateFullUserAuthDTO(
		ctx,
		logger,
		opts.RequestID,
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

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     opts.AppID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found")
			return exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return serviceErr
	}

	userClaims, _, tokenID, exp, err := s.jwt.VerifyUserToken(
		s.GetAppKeyFn(ctx, GetAppKeyFnOptions{
			RequestID: opts.RequestID,
			Name:      AppKeyNameRefresh,
			AppID:     int32(appDTO.ID()),
		}),
		opts.Token,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify user token", "error", err)
		return exceptions.NewUnauthorizedError()
	}
	if userClaims.ID != opts.UserID {
		logger.WarnContext(ctx, "Invalid user ID", "tokenUserId", userClaims.ID, "userId", opts.UserID)
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

	if userDTO.Version() != int(userClaims.Version) {
		logger.WarnContext(ctx, "User version mismatch", "tokenVersion", userClaims.Version, "userVersion", userDTO.Version())
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
