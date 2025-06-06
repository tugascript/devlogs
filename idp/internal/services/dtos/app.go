// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AppDTO struct {
	id        int32
	accountID int32

	Type            string   `json:"type"`
	Name            string   `json:"name"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret,omitempty"`
	CallbackURIs    []string `json:"callback_uris"`
	LogoutURIs      []string `json:"logout_uris"`
	ConfirmationURI string   `json:"confirmation_uri"`
	DefaultScopes   []string `json:"default_scopes"`
	UserRoles       []string `json:"user_roles"`
	UsernameColumn  string   `json:"username_column"`
	Providers       []string `json:"providers"`
	IDTokenTTL      int32    `json:"id_token_ttl"`
}

func (a *AppDTO) ID() int32 {
	return a.id
}

func (a *AppDTO) AccountID() int32 {
	return a.accountID
}

func MapAppToDTO(app *database.App) (AppDTO, *exceptions.ServiceError) {
	defaultScopes, serviceErr := jsonHashMapToSlice(app.DefaultScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	authProviders, serviceErr := jsonHashMapToSlice(app.AuthProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	userRoles, serviceErr := jsonHashMapToSlice(app.UserRoles)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:              app.ID,
		accountID:       app.AccountID,
		Type:            app.Type,
		ClientID:        app.ClientID,
		Name:            app.Name,
		CallbackURIs:    app.CallbackUris,
		LogoutURIs:      app.LogoutUris,
		DefaultScopes:   defaultScopes,
		UserRoles:       userRoles,
		ConfirmationURI: app.ConfirmationUri,
		UsernameColumn:  app.UsernameColumn,
		Providers:       authProviders,
		IDTokenTTL:      app.IDTokenTtl,
	}, nil
}

func MapAppToDTOWithSecret(app *database.App, secret string) (AppDTO, *exceptions.ServiceError) {
	defaultScopes, serviceErr := jsonHashMapToSlice(app.DefaultScopes)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	authProviders, serviceErr := jsonHashMapToSlice(app.AuthProviders)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	userRoles, serviceErr := jsonHashMapToSlice(app.UserRoles)
	if serviceErr != nil {
		return AppDTO{}, serviceErr
	}

	return AppDTO{
		id:              app.ID,
		accountID:       app.AccountID,
		ClientID:        app.ClientID,
		Type:            app.Type,
		ClientSecret:    secret,
		Name:            app.Name,
		CallbackURIs:    app.CallbackUris,
		LogoutURIs:      app.LogoutUris,
		ConfirmationURI: app.ConfirmationUri,
		DefaultScopes:   defaultScopes,
		UserRoles:       userRoles,
		UsernameColumn:  app.UsernameColumn,
		Providers:       authProviders,
		IDTokenTTL:      app.IDTokenTtl,
	}, nil
}
