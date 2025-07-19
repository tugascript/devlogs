// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAccountCredentialsBody struct {
	Scopes      []string `json:"scopes" validate:"required,unique,dive,oneof=account:admin account:users:read account:users:write account:apps:read account:apps:write account:credentials:read account:credentials:write account:auth_providers:read"`
	Alias       string   `json:"alias" validate:"required,min=1,max=50,slug"`
	AuthMethods string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	Issuers     []string `json:"issuers" validate:"required,unique,dive,url"`
	Algorithm   string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
}

type UpdateAccountCredentialsBody struct {
	Scopes  []string `json:"scopes" validate:"required,unique,dive,oneof=account:admin account:users:read account:users:write account:apps:read account:apps:write account:credentials:read account:credentials:write account:auth_providers:read"`
	Alias   string   `json:"alias" validate:"required,min=1,max=50,slug"`
	Issuers []string `json:"issuers" validate:"required,unique,dive,url"`
}
