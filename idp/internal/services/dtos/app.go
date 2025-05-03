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
)

type AppDTO struct {
	id        int
	accountID int
	dek       string

	ClientID       string   `json:"client_id"`
	ClientSecret   string   `json:"client_secret,omitempty"`
	Name           string   `json:"name"`
	CallbackURIs   []string `json:"callback_uris"`
	LogoutURIs     []string `json:"logout_uris"`
	UserScopes     []string `json:"user_scopes"`
	AppProviders   []string `json:"app_providers"`
	IDTokenTTL     int      `json:"id_token_ttl"`
	JwtCryptoSuite string   `json:"jwt_crypto_suite"`
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

func hashMapToSlice(jsonMap []byte) ([]string, *exceptions.ServiceError) {
	hashMap := make(map[string]bool)
	if err := json.Unmarshal(jsonMap, &hashMap); err != nil {
		return nil, exceptions.NewServerError()
	}

	strSlice := make([]string, 0)
	for k := range hashMap {
		strSlice = append(strSlice, k)
	}

	return strSlice, nil
}

func MapAppToDTO(app *database.App) (AppDTO, *exceptions.ServiceError) {
	userScopes, serviceErr := hashMapToSlice(app.UserScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	appProviders, serviceErr := hashMapToSlice(app.AppProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:             int(app.ID),
		accountID:      int(app.AccountID),
		dek:            app.Dek,
		ClientID:       app.ClientID,
		Name:           app.Name,
		CallbackURIs:   app.CallbackUris,
		LogoutURIs:     app.LogoutUris,
		UserScopes:     userScopes,
		AppProviders:   appProviders,
		IDTokenTTL:     int(app.IDTokenTtl),
		JwtCryptoSuite: app.JwtCryptoSuite,
	}, nil
}

func MapAppToDTOWithSecret(app *database.App, secret string) (AppDTO, *exceptions.ServiceError) {
	userScopes, serviceErr := hashMapToSlice(app.UserScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	appProviders, serviceErr := hashMapToSlice(app.AppProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:             int(app.ID),
		ClientID:       app.ClientID,
		ClientSecret:   secret,
		Name:           app.Name,
		CallbackURIs:   app.CallbackUris,
		LogoutURIs:     app.LogoutUris,
		UserScopes:     userScopes,
		AppProviders:   appProviders,
		IDTokenTTL:     int(app.IDTokenTtl),
		JwtCryptoSuite: app.JwtCryptoSuite,
	}, nil
}
