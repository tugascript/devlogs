// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AppDTO struct {
	id        int32
	accountID int32
	version   int32

	Type     database.AppType `json:"type"`
	Name     string           `json:"name"`
	ClientID string           `json:"client_id"`

	ClientURI       string `json:"client_uri,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	TosURI          string `json:"tos_uri,omitempty"`
	PolicyURI       string `json:"policy_uri,omitempty"`
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`

	AuthMethods    []database.AuthMethod      `json:"auth_methods"`
	GrantTypes     []database.GrantType       `json:"grant_types"`
	ResponseTypes  []database.ResponseType    `json:"response_types"`
	DefaultScopes  []database.Scopes          `json:"default_scopes"`
	UsernameColumn database.AppUsernameColumn `json:"username_column"`
	AuthProviders  []database.AuthProvider    `json:"auth_providers"`

	IDTokenTTL      int32 `json:"id_token_ttl"`
	TokenTTL        int32 `json:"token_ttl"`
	RefreshTokenTTL int32 `json:"refresh_token_ttl"`
}

func (a *AppDTO) ID() int32 {
	return a.id
}

func (a *AppDTO) AccountID() int32 {
	return a.accountID
}

func (a *AppDTO) Version() int32 {
	return a.version
}

func MapAppToDTO(app *database.App) AppDTO {
	return AppDTO{
		id:              app.ID,
		accountID:       app.AccountID,
		version:         app.Version,
		Type:            app.Type,
		ClientID:        app.ClientID,
		Name:            app.Name,
		ClientURI:       app.ClientUri.String,
		LogoURI:         app.LogoUri.String,
		TosURI:          app.TosUri.String,
		PolicyURI:       app.PolicyUri.String,
		SoftwareID:      app.SoftwareID.String,
		SoftwareVersion: app.SoftwareVersion.String,
		AuthMethods:     app.AuthMethods,
		GrantTypes:      app.GrantTypes,
		ResponseTypes:   app.ResponseTypes,
		DefaultScopes:   app.DefaultScopes,
		UsernameColumn:  app.UsernameColumn,
		AuthProviders:   app.AuthProviders,
		IDTokenTTL:      app.IDTokenTtl,
		TokenTTL:        app.TokenTtl,
		RefreshTokenTTL: app.RefreshTokenTtl,
	}
}
