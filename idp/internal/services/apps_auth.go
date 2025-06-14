// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

// const appsAuthLocation string = "apps_auth"

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
