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
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const usersAuthLocation string = "users_auth"

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

	appKeyDTO, serviceErr := s.GetOrCreateAppKey(ctx, GetOrCreateAppKeyOptions{
		RequestID:         opts.RequestID,
		AppID:             opts.AppID,
		AppDEK:            opts.AppDEK,
		AppJwtCryptoSuite: tokens.SupportedCryptoSuite(opts.AppJwtCryptoSuite),
		AccountID:         opts.AccountID,
		Name:              AppKeyNameConfirm,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create app key", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	token, err := s.jwt.CreateUserToken(tokens.UserTokenOptions{
		CryptoSuite:     tokens.SupportedCryptoSuite(opts.AppJwtCryptoSuite),
		Type:            tokens.TokenTypeConfirmation,
		PrivateKey:      appKeyDTO.PrivateKey(),
		KID:             appKeyDTO.PublicKID(),
		AccountUsername: opts.AccountUsername,
		UserID:          int32(userDTO.ID),
		UserVersion:     int32(userDTO.Version()),
		UserEmail:       userDTO.Email,
		AppID:           opts.AppID,
		AppClientID:     opts.AppClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create user token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := s.mail.PublishUserConfirmationEmail(ctx, mailer.UserConfirmationEmailOptions{
		RequestID:         opts.RequestID,
		AppName:           opts.AppName,
		Email:             userDTO.Email,
		ConfirmationURI:   opts.AppConfirmationURI,
		ConfirmationToken: token,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish confirmation email", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
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

	confirmationTokenDTO, serviceErr := s.GetAppKey(ctx, GetAppKeyOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		AppDEK:    appDTO.DEK(),
		Name:      AppKeyNameConfirm,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App key not found")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app key", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	userClaims, appClaims, err := s.jwt.VerifyUserToken(tokens.VerifyUserTokenOptions{
		PublicKeyJWK: confirmationTokenDTO.PublicKey(),
		Token:        opts.ConfirmationToken,
	})
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
