// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type AppDynamicRegistrationConfigBody struct {
	AllowedAppTypes                      []string `json:"allowed_app_types" validate:"required,unique,min=1,dive,oneof=web spa native backend device service mcp"`
	DefaultAllowUserRegistration         bool     `json:"default_allow_user_registration"`
	DefaultAuthProviders                 []string `json:"default_auth_providers,omitempty" validate:"omitempty,unique,dive,oneof=local apple facebook github google microsoft"`
	DefaultUsernameColumn                string   `json:"default_username_column,omitempty" validate:"omitempty,oneof=email username both"`
	DefaultAllowedScopes                 []string `json:"default_allowed_scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
	DefaultScopes                        []string `json:"default_scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
	RequireVerifiedDomainsAppTypes      []string `json:"require_verified_domains_app_types,omitempty" validate:"omitempty,unique,dive,oneof=web spa native backend device service mcp"`
	RequireSoftwareStatementAppTypes     []string `json:"require_software_statement_app_types,omitempty" validate:"omitempty,unique,dive,oneof=web spa native backend device service mcp"`
	SoftwareStatementVerificationMethods []string `json:"software_statement_verification_methods,omitempty" validate:"omitempty,unique,min=1,max=2,dive,oneof=manual jwks_uri"`
	RequireInitialAccessTokenAppTypes    []string `json:"require_initial_access_token_app_types,omitempty" validate:"omitempty,unique,dive,oneof=web spa native backend device service mcp"`
	InitialAccessTokenGenerationMethods  []string `json:"initial_access_token_generation_methods,omitempty" validate:"omitempty,unique,min=1,max=2,dive,oneof=manual authorization_code"`
	InitialAccessTokenTtl                int32    `json:"initial_access_token_ttl,omitempty" validate:"omitempty,min=1"`
	InitialAccessTokenMaxUses            int32    `json:"initial_access_token_max_uses,omitempty" validate:"omitempty,min=1"`
	AllowedGrantTypes                    []string `json:"allowed_grant_types,omitempty" validate:"omitempty,unique,min=1,dive,oneof=authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:device_code urn:ietf:params:oauth:grant-type:jwt-bearer"`
	AllowedResponseTypes                 []string `json:"allowed_response_types,omitempty" validate:"omitempty,unique,dive,oneof=code 'code id_token'"`
	AllowedTokenEndpointAuthMethods       []string `json:"allowed_token_endpoint_auth_methods,omitempty" validate:"omitempty,unique,dive,oneof=none client_secret_post client_secret_basic client_secret_jwt private_key_jwt"`
	MaxRedirectUris                      int32    `json:"max_redirect_uris,omitempty" validate:"omitempty,min=1"`
}

