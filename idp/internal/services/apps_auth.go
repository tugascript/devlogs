// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

const appsAuthLocation string = "apps_auth"

type ProcessAppAuthHeaderOptions struct {
	RequestID  string
	AuthHeader string
	AccountID  int32
}

func (s *Services) ProcessAppAuthHeader(
	ctx context.Context,
	opts ProcessAppAuthHeaderOptions,
) (tokens.AppClaims, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsAuthLocation, "ProcessAppAuthHeader").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Processing app auth header")

	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		return tokens.AppClaims{}, serviceErr
	}

	appClaims, err := s.jwt.VerifyAppToken(
		token,
		s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			keyType:   database.TokenKeyTypeClientCredentials,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify app token", "error", err)
		return tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}

	return appClaims, nil
}
