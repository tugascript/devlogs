// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAccountCredentialsBody struct {
	Type                    string   `json:"type" validate:"required,oneof=native service mcp"`
	Name                    string   `json:"name" validate:"required,min=1,max=255"`
	Scopes                  []string `json:"scopes" validate:"required,unique,dive,oneof=email profile account:admin account:users:read account:users:write account:apps:read account:apps:write account:credentials:read account:credentials:write account:auth_providers:read"`
	Transport               string   `json:"transport,omitempty" validate:"required_if=Type mcp,oneof=http https stdio streamable_http"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" validate:"required,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	Domain                  string   `json:"domain,omitempty" validate:"omitempty,fqdn,max=250"`
	ClientURI               string   `json:"client_uri" validate:"required,uri"`
	RedirectURIs            []string `json:"redirect_uris,omitempty" validate:"omitempty,unique,dive,uri"`
	LogoURI                 string   `json:"logo_uri,omitempty" validate:"omitempty,uri"`
	TOSURI                  string   `json:"tos_uri,omitempty" validate:"omitempty,uri"`
	PolicyURI               string   `json:"policy_uri,omitempty" validate:"omitempty,uri"`
	SoftwareID              string   `json:"software_id" validate:"required,min=1,max=100"`
	SoftwareVersion         string   `json:"software_version" validate:"required,min=1,max=100"`
	Algorithm               string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
}

type UpdateAccountCredentialsBody struct {
	Name            string   `json:"name" validate:"required,min=1,max=255"`
	Scopes          []string `json:"scopes" validate:"required,unique,dive,oneof=account:admin account:users:read account:users:write account:apps:read account:apps:write account:credentials:read account:credentials:write account:auth_providers:read"`
	Transport       string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	Domain          string   `json:"domain,omitempty" validate:"omitempty,fqdn,max=250"`
	ClientURI       string   `json:"client_uri" validate:"required,uri"`
	RedirectURIs    []string `json:"redirect_uris,omitempty" validate:"omitempty,unique,dive,uri"`
	LogoURI         string   `json:"logo_uri,omitempty" validate:"omitempty,uri"`
	TOSURI          string   `json:"tos_uri,omitempty" validate:"omitempty,uri"`
	PolicyURI       string   `json:"policy_uri,omitempty" validate:"omitempty,uri"`
	SoftwareVersion string   `json:"software_version,omitempty" validate:"omitempty,min=1,max=100"`
}
