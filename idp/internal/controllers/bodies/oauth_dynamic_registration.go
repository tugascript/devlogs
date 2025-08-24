// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type OAuthDynamicClientRegistrationBody struct {
	RedirectURIs            []string `json:"redirect_uris" validate:"required,min=1,dive,uri"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty" validate:"omitempty,oneof=none client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	ResponseTypes           []string `json:"response_types,omitempty" validate:"omitempty,dive,oneof=none code"`
	GrantTypes              []string `json:"grant_types,omitempty" validate:"omitempty,min=1,dive,oneof=authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:jwt-bearer"`
	ApplicationType         string   `json:"application_type" validate:"required,oneof=native service mcp"`
	ClientName              string   `json:"client_name" validate:"required,min=1,max=255"`
	ClientURI               string   `json:"client_uri" validate:"required,url"`
	LogoURI                 string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	Scope                   string   `json:"scope" validate:"required,multiple_scope"`
	Contacts                []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	TOSURI                  string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI               string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	JWKsURI                 string   `json:"jwks_uri,omitempty" validate:"omitempty,url"`
	JWKs                    []string `json:"jwks,omitempty" validate:"omitempty,json"`
	SoftwareID              string   `json:"software_id,omitempty" validate:"omitempty,max=250"`
	SoftwareVersion         string   `json:"software_version,omitempty" validate:"omitempty,max=250"`
}
