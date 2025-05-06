// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

type AppDTO struct {
	id        int
	accountID int
	dek       string

	Type            string                      `json:"type"`
	ClientID        string                      `json:"client_id"`
	ClientSecret    string                      `json:"client_secret,omitempty"`
	Name            string                      `json:"name"`
	CallbackURIs    []string                    `json:"callback_uris"`
	LogoutURIs      []string                    `json:"logout_uris"`
	ConfirmationURI string                      `json:"confirmation_uri"`
	UserScopes      []string                    `json:"user_scopes"`
	UserRoles       []string                    `json:"user_roles"`
	UsernameColumn  string                      `json:"username_column"`
	ProfileSchema   map[string]any              `json:"profile_schema"`
	Providers       []string                    `json:"providers"`
	IDTokenTTL      int                         `json:"id_token_ttl"`
	JwtCryptoSuite  tokens.SupportedCryptoSuite `json:"jwt_crypto_suite"`
}

func (a *AppDTO) ID() int {
	return a.id
}

func (a *AppDTO) AccountID() int {
	return a.accountID
}

func (a *AppDTO) DEK() string {
	return a.dek
}

func MapAppToDTO(app *database.App) (AppDTO, *exceptions.ServiceError) {
	userScopes, serviceErr := hashMapToSlice(app.UserScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	authProviders, serviceErr := hashMapToSlice(app.AuthProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	userRoles, serviceErr := hashMapToSlice(app.UserRoles)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	profileSchema := make(map[string]any)
	if err := json.Unmarshal(app.ProfileSchema, &profileSchema); err != nil {
		return AppDTO{}, exceptions.NewServerError()
	}

	jwtCryptoSuite, serviceErr := GetJwtCryptoSuite(app.JwtCryptoSuite)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:              int(app.ID),
		accountID:       int(app.AccountID),
		dek:             app.Dek,
		Type:            app.Type,
		ClientID:        app.ClientID,
		Name:            app.Name,
		CallbackURIs:    app.CallbackUris,
		LogoutURIs:      app.LogoutUris,
		UserScopes:      userScopes,
		UserRoles:       userRoles,
		ConfirmationURI: app.ConfirmationUri,
		UsernameColumn:  app.UsernameColumn,
		ProfileSchema:   profileSchema,
		Providers:       authProviders,
		IDTokenTTL:      int(app.IDTokenTtl),
		JwtCryptoSuite:  jwtCryptoSuite,
	}, nil
}

func MapAppToDTOWithSecret(app *database.App, secret string) (AppDTO, *exceptions.ServiceError) {
	userScopes, serviceErr := hashMapToSlice(app.UserScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	authProviders, serviceErr := hashMapToSlice(app.AuthProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	userRoles, serviceErr := hashMapToSlice(app.UserRoles)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	profileSchema := make(map[string]any)
	if err := json.Unmarshal(app.ProfileSchema, &profileSchema); err != nil {
		return AppDTO{}, exceptions.NewServerError()
	}

	jwtCryptoSuite, serviceErr := GetJwtCryptoSuite(app.JwtCryptoSuite)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:              int(app.ID),
		accountID:       int(app.AccountID),
		dek:             app.Dek,
		ClientID:        app.ClientID,
		Type:            app.Type,
		ClientSecret:    secret,
		Name:            app.Name,
		CallbackURIs:    app.CallbackUris,
		LogoutURIs:      app.LogoutUris,
		ConfirmationURI: app.ConfirmationUri,
		UserScopes:      userScopes,
		UserRoles:       userRoles,
		UsernameColumn:  app.UsernameColumn,
		Providers:       authProviders,
		IDTokenTTL:      int(app.IDTokenTtl),
		ProfileSchema:   profileSchema,
		JwtCryptoSuite:  jwtCryptoSuite,
	}, nil
}
