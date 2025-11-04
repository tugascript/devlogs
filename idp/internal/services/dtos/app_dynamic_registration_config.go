// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import "github.com/tugascript/devlogs/idp/internal/providers/database"

type AppDynamicRegistrationConfigDTO struct {
	id int32

	AllowedAppTypes                      []database.AppType                             `json:"allowed_app_types"`
	WhitelistedDomains                   []string                                       `json:"whitelisted_domains"`
	DefaultAllowUserRegistration         bool                                           `json:"default_allow_user_registration"`
	DefaultAuthProviders                 []database.AuthProvider                        `json:"default_auth_providers"`
	DefaultUsernameColumn                database.AppUsernameColumn                     `json:"default_username_column"`
	DefaultAllowedScopes                 []database.Scopes                              `json:"default_allowed_scopes"`
	DefaultScopes                        []database.Scopes                              `json:"default_scopes"`
	RequireVerifiedDomainsAppTypes       []database.AppType                             `json:"require_verified_domains_app_types"`
	RequireSoftwareStatementAppTypes     []database.AppType                             `json:"require_software_statement_app_types"`
	SoftwareStatementVerificationMethods []database.SoftwareStatementVerificationMethod `json:"software_statement_verification_methods"`
	RequireInitialAccessTokenAppTypes    []database.AppType                             `json:"require_initial_access_token_app_types"`
	InitialAccessTokenGenerationMethods  []database.InitialAccessTokenGenerationMethod  `json:"initial_access_token_generation_methods"`
	InitialAccessTokenTtl                int32                                          `json:"initial_access_token_ttl"`
	InitialAccessTokenMaxUses            int32                                          `json:"initial_access_token_max_uses"`
	AllowedGrantTypes                    []database.GrantType                           `json:"allowed_grant_types"`
	AllowedResponseTypes                 []database.ResponseType                        `json:"allowed_response_types"`
	AllowedTokenEndpointAuthMethods      []database.AuthMethod                          `json:"allowed_token_endpoint_auth_methods"`
	MaxRedirectUris                      int32                                          `json:"max_redirect_uris"`
}

func (a *AppDynamicRegistrationConfigDTO) ID() int32 {
	return a.id
}

func MapAppDynamicRegistrationConfigToDTO(
	config *database.AppDynamicRegistrationConfig,
) AppDynamicRegistrationConfigDTO {
	return AppDynamicRegistrationConfigDTO{
		id:                                   config.ID,
		AllowedAppTypes:                      config.AllowedAppTypes,
		DefaultAllowUserRegistration:         config.DefaultAllowUserRegistration,
		DefaultAuthProviders:                 config.DefaultAuthProviders,
		DefaultUsernameColumn:                config.DefaultUsernameColumn,
		DefaultAllowedScopes:                 config.DefaultAllowedScopes,
		DefaultScopes:                        config.DefaultScopes,
		RequireVerifiedDomainsAppTypes:       config.RequireVerifiedDomainsAppTypes,
		RequireSoftwareStatementAppTypes:     config.RequireSoftwareStatementAppTypes,
		SoftwareStatementVerificationMethods: config.SoftwareStatementVerificationMethods,
		RequireInitialAccessTokenAppTypes:    config.RequireInitialAccessTokenAppTypes,
		InitialAccessTokenGenerationMethods:  config.InitialAccessTokenGenerationMethods,
		InitialAccessTokenTtl:                config.InitialAccessTokenTtl,
		InitialAccessTokenMaxUses:            config.InitialAccessTokenMaxUses,
		AllowedGrantTypes:                    config.AllowedGrantTypes,
		AllowedResponseTypes:                 config.AllowedResponseTypes,
		AllowedTokenEndpointAuthMethods:      config.AllowedTokenEndpointAuthMethods,
		MaxRedirectUris:                      config.MaxRedirectUris,
	}
}
