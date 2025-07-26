// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type RelatedAppDTO struct {
	Type     database.AppType `json:"type"`
	Name     string           `json:"name"`
	ClientID string           `json:"client_id"`
	Links    LinksSelfDTO     `json:"links"`
}

func newRelatedAppDTO(
	app *database.App,
	backendDomain string,
	route string,
) RelatedAppDTO {
	return RelatedAppDTO{
		Type:     app.Type,
		Name:     app.Name,
		ClientID: app.ClientID,
		Links:    NewLinksSelfDTO(backendDomain, route),
	}
}

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
	DefaultScopes  []database.Scopes          `json:"default_scopes"`
	UsernameColumn database.AppUsernameColumn `json:"username_column"`
	AuthProviders  []database.AuthProvider    `json:"auth_providers"`

	IDTokenTTL      int32 `json:"id_token_ttl"`
	TokenTTL        int32 `json:"token_ttl"`
	RefreshTokenTTL int32 `json:"refresh_token_ttl,omitempty"`

	CallbackURIs        []string                     `json:"callback_uris,omitempty"`
	LogoutURIs          []string                     `json:"logout_uris,omitempty"`
	AllowedOrigins      []string                     `json:"allowed_origins,omitempty"`
	CodeChallengeMethod database.CodeChallengeMethod `json:"code_challenge_method,omitempty"`

	ClientSecretID  string    `json:"client_secret_id,omitempty"`
	ClientSecret    string    `json:"client_secret,omitempty"`
	ClientSecretJWK utils.JWK `json:"client_secret_jwk,omitempty"`
	ClientSecretExp int64     `json:"client_secret_exp,omitempty"`

	Issuers          []string `json:"issuers,omitempty"`
	ConfirmationURL  string   `json:"confirmation_url,omitempty"`
	ResetPasswordURL string   `json:"reset_password_url,omitempty"`

	RelatedApps []RelatedAppDTO `json:"related_apps,omitempty"`

	UsersAuthMethods []database.AuthMethod `json:"users_auth_methods,omitempty"`
	UsersGrantTypes  []database.GrantType  `json:"users_auth_providers,omitempty"`
	AllowedDomains   []string              `json:"allowed_domains,omitempty"`
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
		ClientURI:       app.ClientUri,
		LogoURI:         app.LogoUri.String,
		TosURI:          app.TosUri.String,
		PolicyURI:       app.PolicyUri.String,
		SoftwareID:      app.SoftwareID.String,
		SoftwareVersion: app.SoftwareVersion.String,
		AuthMethods:     app.AuthMethods,
		GrantTypes:      app.GrantTypes,
		DefaultScopes:   app.DefaultScopes,
		UsernameColumn:  app.UsernameColumn,
		AuthProviders:   app.AuthProviders,
		IDTokenTTL:      app.IDTokenTtl,
		TokenTTL:        app.TokenTtl,
		RefreshTokenTTL: app.RefreshTokenTtl,
	}
}

func MapWebAppToDTO(
	app *database.App,
	authConfig *database.AppAuthCodeConfig,
) AppDTO {
	var allowedOrigins []string
	if len(authConfig.AllowedOrigins) > 0 {
		allowedOrigins = authConfig.AllowedOrigins
	}

	return AppDTO{
		id:                  app.ID,
		accountID:           app.AccountID,
		version:             app.Version,
		Type:                app.Type,
		Name:                app.Name,
		ClientID:            app.ClientID,
		ClientURI:           app.ClientUri,
		LogoURI:             app.LogoUri.String,
		TosURI:              app.TosUri.String,
		PolicyURI:           app.PolicyUri.String,
		SoftwareID:          app.SoftwareID.String,
		SoftwareVersion:     app.SoftwareVersion.String,
		AuthMethods:         app.AuthMethods,
		GrantTypes:          app.GrantTypes,
		DefaultScopes:       app.DefaultScopes,
		UsernameColumn:      app.UsernameColumn,
		AuthProviders:       app.AuthProviders,
		IDTokenTTL:          app.IDTokenTtl,
		TokenTTL:            app.TokenTtl,
		RefreshTokenTTL:     app.RefreshTokenTtl,
		CallbackURIs:        authConfig.CallbackUris,
		LogoutURIs:          authConfig.LogoutUris,
		AllowedOrigins:      allowedOrigins,
		CodeChallengeMethod: authConfig.CodeChallengeMethod,
	}
}

func MapWebAppWithSecretToDTO(
	app *database.App,
	authConfig *database.AppAuthCodeConfig,
	secretID string,
	secret string,
	expiresAt time.Time,
) AppDTO {
	var allowedOrigins []string
	if len(authConfig.AllowedOrigins) > 0 {
		allowedOrigins = authConfig.AllowedOrigins
	}

	return AppDTO{
		id:                  app.ID,
		accountID:           app.AccountID,
		version:             app.Version,
		Type:                app.Type,
		Name:                app.Name,
		ClientID:            app.ClientID,
		ClientURI:           app.ClientUri,
		LogoURI:             app.LogoUri.String,
		TosURI:              app.TosUri.String,
		PolicyURI:           app.PolicyUri.String,
		SoftwareID:          app.SoftwareID.String,
		SoftwareVersion:     app.SoftwareVersion.String,
		AuthMethods:         app.AuthMethods,
		GrantTypes:          app.GrantTypes,
		DefaultScopes:       app.DefaultScopes,
		UsernameColumn:      app.UsernameColumn,
		AuthProviders:       app.AuthProviders,
		IDTokenTTL:          app.IDTokenTtl,
		TokenTTL:            app.TokenTtl,
		RefreshTokenTTL:     app.RefreshTokenTtl,
		CallbackURIs:        authConfig.CallbackUris,
		LogoutURIs:          authConfig.LogoutUris,
		AllowedOrigins:      allowedOrigins,
		CodeChallengeMethod: authConfig.CodeChallengeMethod,
		ClientSecretID:      secret,
		ClientSecret:        fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp:     expiresAt.Unix(),
	}
}

func MapWebAppWithJWKToDTO(
	app *database.App,
	authConfig *database.AppAuthCodeConfig,
	jwk utils.JWK,
	exp time.Time,
) AppDTO {
	var allowedOrigins []string
	if len(authConfig.AllowedOrigins) > 0 {
		allowedOrigins = authConfig.AllowedOrigins
	}

	return AppDTO{
		id:                  app.ID,
		accountID:           app.AccountID,
		version:             app.Version,
		Type:                app.Type,
		Name:                app.Name,
		ClientID:            app.ClientID,
		ClientURI:           app.ClientUri,
		LogoURI:             app.LogoUri.String,
		TosURI:              app.TosUri.String,
		PolicyURI:           app.PolicyUri.String,
		SoftwareID:          app.SoftwareID.String,
		SoftwareVersion:     app.SoftwareVersion.String,
		AuthMethods:         app.AuthMethods,
		GrantTypes:          app.GrantTypes,
		DefaultScopes:       app.DefaultScopes,
		UsernameColumn:      app.UsernameColumn,
		AuthProviders:       app.AuthProviders,
		IDTokenTTL:          app.IDTokenTtl,
		TokenTTL:            app.TokenTtl,
		RefreshTokenTTL:     app.RefreshTokenTtl,
		CallbackURIs:        authConfig.CallbackUris,
		LogoutURIs:          authConfig.LogoutUris,
		AllowedOrigins:      allowedOrigins,
		CodeChallengeMethod: authConfig.CodeChallengeMethod,
		ClientSecretID:      jwk.GetKeyID(),
		ClientSecretJWK:     jwk,
		ClientSecretExp:     exp.Unix(),
	}
}

func MapSPAAppToDTO(
	app *database.App,
	authConfig *database.AppAuthCodeConfig,
) AppDTO {
	return AppDTO{
		id:                  app.ID,
		accountID:           app.AccountID,
		version:             app.Version,
		Type:                app.Type,
		Name:                app.Name,
		ClientID:            app.ClientID,
		ClientURI:           app.ClientUri,
		LogoURI:             app.LogoUri.String,
		TosURI:              app.TosUri.String,
		PolicyURI:           app.PolicyUri.String,
		SoftwareID:          app.SoftwareID.String,
		SoftwareVersion:     app.SoftwareVersion.String,
		AuthMethods:         app.AuthMethods,
		GrantTypes:          app.GrantTypes,
		DefaultScopes:       app.DefaultScopes,
		UsernameColumn:      app.UsernameColumn,
		AuthProviders:       app.AuthProviders,
		IDTokenTTL:          app.IDTokenTtl,
		TokenTTL:            app.TokenTtl,
		RefreshTokenTTL:     app.RefreshTokenTtl,
		CallbackURIs:        authConfig.CallbackUris,
		LogoutURIs:          authConfig.LogoutUris,
		AllowedOrigins:      authConfig.AllowedOrigins,
		CodeChallengeMethod: authConfig.CodeChallengeMethod,
	}
}

func MapNativeAppToDTO(
	app *database.App,
	authConfig *database.AppAuthCodeConfig,
) AppDTO {
	return AppDTO{
		id:                  app.ID,
		accountID:           app.AccountID,
		version:             app.Version,
		Type:                app.Type,
		Name:                app.Name,
		ClientID:            app.ClientID,
		ClientURI:           app.ClientUri,
		LogoURI:             app.LogoUri.String,
		TosURI:              app.TosUri.String,
		PolicyURI:           app.PolicyUri.String,
		SoftwareID:          app.SoftwareID.String,
		SoftwareVersion:     app.SoftwareVersion.String,
		AuthMethods:         app.AuthMethods,
		GrantTypes:          app.GrantTypes,
		DefaultScopes:       app.DefaultScopes,
		UsernameColumn:      app.UsernameColumn,
		AuthProviders:       app.AuthProviders,
		IDTokenTTL:          app.IDTokenTtl,
		TokenTTL:            app.TokenTtl,
		RefreshTokenTTL:     app.RefreshTokenTtl,
		CallbackURIs:        authConfig.CallbackUris,
		LogoutURIs:          authConfig.LogoutUris,
		CodeChallengeMethod: authConfig.CodeChallengeMethod,
	}
}

func MapBackendAppWithJWKToDTO(
	app *database.App,
	serverCfg *database.AppServerConfig,
	jwk utils.JWK,
	exp time.Time,
) AppDTO {
	return AppDTO{
		id:               app.ID,
		accountID:        app.AccountID,
		version:          app.Version,
		Type:             app.Type,
		Name:             app.Name,
		ClientID:         app.ClientID,
		ClientURI:        app.ClientUri,
		LogoURI:          app.LogoUri.String,
		TosURI:           app.TosUri.String,
		PolicyURI:        app.PolicyUri.String,
		SoftwareID:       app.SoftwareID.String,
		SoftwareVersion:  app.SoftwareVersion.String,
		AuthMethods:      app.AuthMethods,
		GrantTypes:       app.GrantTypes,
		DefaultScopes:    app.DefaultScopes,
		UsernameColumn:   app.UsernameColumn,
		AuthProviders:    app.AuthProviders,
		IDTokenTTL:       app.IDTokenTtl,
		TokenTTL:         app.TokenTtl,
		RefreshTokenTTL:  app.RefreshTokenTtl,
		ClientSecretID:   jwk.GetKeyID(),
		ClientSecretJWK:  jwk,
		ClientSecretExp:  exp.Unix(),
		ConfirmationURL:  serverCfg.ConfirmationUrl,
		ResetPasswordURL: serverCfg.ResetPasswordUrl,
		Issuers:          serverCfg.Issuers,
	}
}

func MapDeviceAppToDTO(
	app *database.App,
	relatedApps []database.App,
	backendDomain string,
) AppDTO {
	return AppDTO{
		id:              app.ID,
		accountID:       app.AccountID,
		version:         app.Version,
		Type:            app.Type,
		Name:            app.Name,
		ClientID:        app.ClientID,
		ClientURI:       app.ClientUri,
		LogoURI:         app.LogoUri.String,
		TosURI:          app.TosUri.String,
		PolicyURI:       app.PolicyUri.String,
		SoftwareID:      app.SoftwareID.String,
		SoftwareVersion: app.SoftwareVersion.String,
		AuthMethods:     app.AuthMethods,
		GrantTypes:      app.GrantTypes,
		DefaultScopes:   app.DefaultScopes,
		UsernameColumn:  app.UsernameColumn,
		AuthProviders:   app.AuthProviders,
		IDTokenTTL:      app.IDTokenTtl,
		TokenTTL:        app.TokenTtl,
		RefreshTokenTTL: app.RefreshTokenTtl,
		RelatedApps: utils.MapSlice(relatedApps, func(ra *database.App) RelatedAppDTO {
			return newRelatedAppDTO(ra, backendDomain, paths.AppsBase)
		}),
	}
}

func MapServiceAppWithJWKToDTO(
	app *database.App,
	serviceCfg *database.AppServiceConfig,
	jwk utils.JWK,
	exp time.Time,
) AppDTO {
	return AppDTO{
		id:               app.ID,
		accountID:        app.AccountID,
		version:          app.Version,
		Type:             app.Type,
		Name:             app.Name,
		ClientID:         app.ClientID,
		ClientURI:        app.ClientUri,
		LogoURI:          app.LogoUri.String,
		TosURI:           app.TosUri.String,
		PolicyURI:        app.PolicyUri.String,
		SoftwareID:       app.SoftwareID.String,
		SoftwareVersion:  app.SoftwareVersion.String,
		AuthMethods:      app.AuthMethods,
		GrantTypes:       app.GrantTypes,
		DefaultScopes:    app.DefaultScopes,
		UsernameColumn:   app.UsernameColumn,
		AuthProviders:    app.AuthProviders,
		IDTokenTTL:       app.IDTokenTtl,
		TokenTTL:         app.TokenTtl,
		RefreshTokenTTL:  app.RefreshTokenTtl,
		AllowedDomains:   serviceCfg.AllowedDomains,
		UsersAuthMethods: serviceCfg.AuthMethods,
		UsersGrantTypes:  serviceCfg.GrantTypes,
		ClientSecretID:   jwk.GetKeyID(),
		ClientSecretJWK:  jwk,
		ClientSecretExp:  exp.Unix(),
		Issuers:          serviceCfg.Issuers,
	}
}

func MapBackendAppToDTO(
	app *database.App,
	serverCfg *database.AppServerConfig,
) AppDTO {
	return AppDTO{
		id:               app.ID,
		accountID:        app.AccountID,
		version:          app.Version,
		Type:             app.Type,
		Name:             app.Name,
		ClientID:         app.ClientID,
		ClientURI:        app.ClientUri,
		LogoURI:          app.LogoUri.String,
		TosURI:           app.TosUri.String,
		PolicyURI:        app.PolicyUri.String,
		SoftwareID:       app.SoftwareID.String,
		SoftwareVersion:  app.SoftwareVersion.String,
		AuthMethods:      app.AuthMethods,
		GrantTypes:       app.GrantTypes,
		DefaultScopes:    app.DefaultScopes,
		UsernameColumn:   app.UsernameColumn,
		AuthProviders:    app.AuthProviders,
		IDTokenTTL:       app.IDTokenTtl,
		TokenTTL:         app.TokenTtl,
		RefreshTokenTTL:  app.RefreshTokenTtl,
		ConfirmationURL:  serverCfg.ConfirmationUrl,
		ResetPasswordURL: serverCfg.ResetPasswordUrl,
		Issuers:          serverCfg.Issuers,
	}
}

func MapServiceAppToDTO(
	app *database.App,
	serviceCfg *database.AppServiceConfig,
) AppDTO {
	return AppDTO{
		id:               app.ID,
		accountID:        app.AccountID,
		version:          app.Version,
		Type:             app.Type,
		Name:             app.Name,
		ClientID:         app.ClientID,
		ClientURI:        app.ClientUri,
		LogoURI:          app.LogoUri.String,
		TosURI:           app.TosUri.String,
		PolicyURI:        app.PolicyUri.String,
		SoftwareID:       app.SoftwareID.String,
		SoftwareVersion:  app.SoftwareVersion.String,
		AuthMethods:      app.AuthMethods,
		GrantTypes:       app.GrantTypes,
		DefaultScopes:    app.DefaultScopes,
		UsernameColumn:   app.UsernameColumn,
		AuthProviders:    app.AuthProviders,
		IDTokenTTL:       app.IDTokenTtl,
		TokenTTL:         app.TokenTtl,
		RefreshTokenTTL:  app.RefreshTokenTtl,
		AllowedDomains:   serviceCfg.AllowedDomains,
		UsersAuthMethods: serviceCfg.AuthMethods,
		UsersGrantTypes:  serviceCfg.GrantTypes,
		Issuers:          serviceCfg.Issuers,
	}
}
