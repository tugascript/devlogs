// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appsAuthLocation string = "apps_auth"

func (s *Services) ProcessAppAuthHeader(
	authHeader string,
) (tokens.AppClaims, string, *exceptions.ServiceError) {
	token, serviceErr := extractAuthHeaderToken(authHeader)
	if serviceErr != nil {
		return tokens.AppClaims{}, "", serviceErr
	}

	appClaims, accountUsername, err := s.jwt.VerifyAppToken(token)
	if err != nil {
		return tokens.AppClaims{}, "", exceptions.NewUnauthorizedError()
	}

	return appClaims, accountUsername, nil
}

type AppLoginOptions struct {
	RequestID       string
	AccountUsername string
	AccountID       int32
	ClientID        string
	ClientSecret    string
}

func (s *Services) AppLogin(
	ctx context.Context,
	opts AppLoginOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsAuthLocation, "AppLogin").With(
		"accountID", opts.AccountID,
		"clientID", opts.ClientID,
	)

	appDTO, serviceErr := s.GetAppByClientIDAndAccountID(ctx, GetAppByClientIDAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found", "error", serviceErr)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by clientID", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	verified, err := utils.CompareHash(opts.ClientSecret, appDTO.HashedSecret())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare hash", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if !verified {
		logger.WarnContext(ctx, "Invalid client secret")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	appToken, err := s.jwt.CreateAppToken(tokens.AppTokenOptions{
		ClientID:        appDTO.ClientID,
		Version:         appDTO.Version(),
		AccountUsername: opts.AccountUsername,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "App logged in successfully")
	return dtos.NewAuthDTO(appToken, s.jwt.GetAppTTL()), nil
}
