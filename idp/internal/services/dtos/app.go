// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AppDTO struct {
	Registration *ClientRegistrationDTO `json:"-"`
	id           int64
	accountID    int64
	version      int32

	AppType        database.AppType        `json:"app_type"`
	ClientName     string                  `json:"client_name"`
	ClientID       string                  `json:"client_id"`
	Domain         string                  `json:"domain"`
	CreationMethod database.CreationMethod `json:"creation_method"`

	ClientURI       string `json:"client_uri,omitempty"`
	LogoURI         string `json:"logo_uri,omitempty"`
	TosURI          string `json:"tos_uri,omitempty"`
	PolicyURI       string `json:"policy_uri,omitempty"`
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`

	TokenEndpointAuthMethod database.AuthMethod        `json:"token_endpoint_auth_method"`
	GrantTypes              []database.GrantType       `json:"grant_types"`
	DefaultScopes           []string                   `json:"default_scopes"`
	Scopes                  []string                   `json:"scopes"`
	UsernameColumn          database.AppUsernameColumn `json:"username_column"`
	AuthProviders           []database.AuthProvider    `json:"auth_providers"`
	RedirectURIs            []string                   `json:"redirect_uris,omitempty"`
	ResponseTypes           []database.ResponseType    `json:"response_types,omitempty"`

	AccessTokenTTL      int32 `json:"access_token_ttl"`
	IDTokenTTL          int32 `json:"id_token_ttl,omitempty"`
	RefreshTokenIdleTTL int32 `json:"refresh_token_idle_ttl,omitempty"`
	RefreshTokenTTL     int32 `json:"refresh_token_ttl,omitempty"`

	ClientSecretID  string    `json:"client_secret_id,omitempty"`
	ClientSecret    string    `json:"client_secret,omitempty"`
	ClientSecretJWK utils.JWK `json:"client_secret_jwk,omitempty"`
	ClientSecretExp int64     `json:"client_secret_exp,omitempty"`
}

func (a *AppDTO) ID() int64 {
	return a.id
}

func (a *AppDTO) AccountID() int64 {
	return a.accountID
}

func (a *AppDTO) Version() int32 {
	return a.version
}

func (a *AppDTO) UnmarshalJSON(data []byte) error {
	type Alias AppDTO
	aux := &struct {
		ClientSecretJWK json.RawMessage `json:"client_secret_jwk,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if aux.ClientSecretJWK != nil {
		jwk, err := utils.JsonToJWK(aux.ClientSecretJWK)
		if err != nil {
			return err
		}
		a.ClientSecretJWK = jwk
	}
	return nil
}

func mapScopes(scopes []database.Scopes, customScopes []string) []string {
	allScopes := make([]string, len(scopes)+len(customScopes))
	for i, scope := range scopes {
		allScopes[i] = string(scope)
	}
	for i, scope := range customScopes {
		allScopes[len(scopes)+i] = scope
	}
	return allScopes
}

func MapAppToDTO(app *database.App) AppDTO {
	return AppDTO{
		id:                      app.ID,
		accountID:               app.AccountID,
		version:                 app.Version,
		AppType:                 app.AppType,
		ClientName:              app.ClientName,
		ClientID:                app.ClientID,
		Domain:                  app.Domain,
		CreationMethod:          app.CreationMethod,
		ClientURI:               app.ClientUri,
		LogoURI:                 app.LogoUri.String,
		TosURI:                  app.TosUri.String,
		PolicyURI:               app.PolicyUri.String,
		SoftwareID:              app.SoftwareID.String,
		SoftwareVersion:         app.SoftwareVersion.String,
		TokenEndpointAuthMethod: app.TokenEndpointAuthMethod,
		GrantTypes:              app.GrantTypes,
		DefaultScopes:           mapScopes(app.DefaultScopes, app.DefaultCustomScopes),
		Scopes:                  mapScopes(app.Scopes, app.CustomScopes),
		UsernameColumn:          app.UsernameColumn,
		AuthProviders:           app.AuthProviders,
		RedirectURIs:            app.RedirectUris,
		ResponseTypes:           app.ResponseTypes,
		AccessTokenTTL:          app.AccessTokenTtl,
		IDTokenTTL:              app.IDTokenTtl.Int32,
		RefreshTokenIdleTTL:     app.RefreshTokenIdleTtl.Int32,
		RefreshTokenTTL:         app.RefreshTokenTtl.Int32,
	}
}

func MapWebAppWithSecretToDTO(
	app *database.App,
	secretID string,
	secret string,
	expiresAt time.Time,
) AppDTO {
	return AppDTO{
		id:                      app.ID,
		accountID:               app.AccountID,
		version:                 app.Version,
		AppType:                 app.AppType,
		ClientName:              app.ClientName,
		ClientID:                app.ClientID,
		Domain:                  app.Domain,
		CreationMethod:          app.CreationMethod,
		ClientURI:               app.ClientUri,
		LogoURI:                 app.LogoUri.String,
		TosURI:                  app.TosUri.String,
		PolicyURI:               app.PolicyUri.String,
		SoftwareID:              app.SoftwareID.String,
		SoftwareVersion:         app.SoftwareVersion.String,
		TokenEndpointAuthMethod: app.TokenEndpointAuthMethod,
		GrantTypes:              app.GrantTypes,
		DefaultScopes:           mapScopes(app.DefaultScopes, app.DefaultCustomScopes),
		Scopes:                  mapScopes(app.Scopes, app.CustomScopes),
		UsernameColumn:          app.UsernameColumn,
		AuthProviders:           app.AuthProviders,
		RedirectURIs:            app.RedirectUris,
		ResponseTypes:           app.ResponseTypes,
		AccessTokenTTL:          app.AccessTokenTtl,
		IDTokenTTL:              app.IDTokenTtl.Int32,
		RefreshTokenIdleTTL:     app.RefreshTokenIdleTtl.Int32,
		RefreshTokenTTL:         app.RefreshTokenTtl.Int32,
		ClientSecretID:          secretID,
		ClientSecret:            fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp:         expiresAt.Unix(),
	}
}

func MapWebAppWithJWKToDTO(app *database.App, jwk utils.JWK, exp time.Time) AppDTO {
	return AppDTO{
		id:                      app.ID,
		accountID:               app.AccountID,
		version:                 app.Version,
		AppType:                 app.AppType,
		ClientName:              app.ClientName,
		ClientID:                app.ClientID,
		Domain:                  app.Domain,
		CreationMethod:          app.CreationMethod,
		ClientURI:               app.ClientUri,
		LogoURI:                 app.LogoUri.String,
		TosURI:                  app.TosUri.String,
		PolicyURI:               app.PolicyUri.String,
		SoftwareID:              app.SoftwareID.String,
		SoftwareVersion:         app.SoftwareVersion.String,
		TokenEndpointAuthMethod: app.TokenEndpointAuthMethod,
		GrantTypes:              app.GrantTypes,
		DefaultScopes:           mapScopes(app.DefaultScopes, app.DefaultCustomScopes),
		Scopes:                  mapScopes(app.DefaultScopes, app.DefaultCustomScopes),
		UsernameColumn:          app.UsernameColumn,
		AuthProviders:           app.AuthProviders,
		RedirectURIs:            app.RedirectUris,
		ResponseTypes:           app.ResponseTypes,
		AccessTokenTTL:          app.AccessTokenTtl,
		IDTokenTTL:              app.IDTokenTtl.Int32,
		RefreshTokenIdleTTL:     app.RefreshTokenIdleTtl.Int32,
		RefreshTokenTTL:         app.RefreshTokenTtl.Int32,
		ClientSecretID:          jwk.GetKeyID(),
		ClientSecretJWK:         jwk,
		ClientSecretExp:         exp.Unix(),
	}
}
