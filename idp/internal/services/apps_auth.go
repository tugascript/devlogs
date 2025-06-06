// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"strings"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appsAuthLocation string = "apps_auth"

func (s *Services) ProcessAppAuthHeader(
	authHeader string,
) (int32, string, *exceptions.ServiceError) {
	authHeaderSlice := strings.Split(authHeader, " ")

	if len(authHeaderSlice) != 2 {
		return 0, "", exceptions.NewUnauthorizedError()
	}
	if utils.Lowered(authHeaderSlice[0]) != "bearer" {
		return 0, "", exceptions.NewUnauthorizedError()
	}

	appId, appClientID, err := s.jwt.VerifyAppToken(authHeaderSlice[1])
	if err != nil {
		return 0, "", exceptions.NewUnauthorizedError()
	}

	return appId, appClientID, nil
}
