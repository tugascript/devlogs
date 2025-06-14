// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	AuthMethodBothClientSecrets string = "both_client_secrets"
	AuthMethodPrivateKeyJwt     string = "private_key_jwt"
	AuthMethodClientSecretBasic string = "client_secret_basic"
	AuthMethodClientSecretPost  string = "client_secret_post"
	AuthMethodNone              string = "none"

	AuthProviderEmail            string = "email"
	AuthProviderGoogle           string = "google"
	AuthProviderGitHub           string = "github"
	AuthProviderApple            string = "apple"
	AuthProviderMicrosoft        string = "microsoft"
	AuthProviderFacebook         string = "facebook"
	AuthProviderUsernamePassword string = "username_password"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"

	UsernameColumnEmail    string = "email"
	UsernameColumnUsername string = "username"
	UsernameColumnBoth     string = "both"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
		Layer:     utils.ServicesLogLayer,
		Location:  location,
		Method:    function,
		RequestID: requestID,
	})
}

func mapSliceToJsonMap(scopes []string) ([]byte, error) {
	scopeMap := make(map[string]bool)

	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	jsonMap, err := json.Marshal(scopeMap)
	if err != nil {
		return nil, err
	}

	return jsonMap, nil
}

func extractAuthHeaderToken(ah string) (string, *exceptions.ServiceError) {
	if ah == "" {
		return "", exceptions.NewUnauthorizedError()
	}

	ahSlice := strings.Split(strings.TrimSpace(ah), " ")
	if len(ahSlice) != 2 {
		return "", exceptions.NewUnauthorizedError()
	}
	if utils.Lowered(ahSlice[0]) != "bearer" {
		return "", exceptions.NewUnauthorizedError()
	}

	return ahSlice[1], nil
}

func mapAuthMethod(authMethod string) ([]database.AuthMethod, *exceptions.ServiceError) {
	if authMethod == AuthMethodBothClientSecrets {
		return []database.AuthMethod{
			database.AuthMethodClientSecretBasic,
			database.AuthMethodClientSecretPost,
		}, nil
	}

	am := database.AuthMethod(authMethod)
	switch am {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost,
		database.AuthMethodPrivateKeyJwt, database.AuthMethodNone:
		return []database.AuthMethod{am}, nil
	default:
		return nil, exceptions.NewValidationError("invalid auth method")
	}
}
