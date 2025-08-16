// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type AccountDynamicRegistrationConfigBody struct {
	AccountCredentialsTypes                  []string `json:"account_credentials_types" validate:"required,unique,min=1,max=3,oneof=native service mcp"`
	WhitelistedDomains                       []string `json:"whitelisted_domains" validate:"omitempty,unique,min=1,max=250,dive,fqdn"`
	RequireSoftwareStatementCredentialTypes  []string `json:"require_software_statement_credential_types" validate:"omitempty,unique,min=1,max=3,oneof=native service mcp"`
	SoftwareStatementVerificationMethods     []string `json:"software_statement_verification_methods" validate:"omitempty,unique,min=1,max=2,oneof=manual jwks_uri"`
	RequireInitialAccessTokenCredentialTypes []string `json:"require_initial_access_token_credential_types" validate:"omitempty,unique,min=1,max=3,oneof=native service mcp"`
	InitialAccessTokenGenerationMethods      []string `json:"initial_access_token_generation_methods" validate:"omitempty,unique,min=1,max=2,oneof=manual authorization_code"`
}
