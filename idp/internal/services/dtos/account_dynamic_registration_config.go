// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import "github.com/tugascript/devlogs/idp/internal/providers/database"

type AccountDynamicRegistrationConfigDTO struct {
	id int32

	CredentialsTypes                         []database.AccountCredentialsType              `json:"credentials_types"`
	WhitelistedDomains                       []string                                       `json:"whitelisted_domains"`
	RequireSoftwareStatementCredentialTypes  []database.AccountCredentialsType              `json:"require_software_statement_credential_types"`
	SoftwareStatementVerificationMethods     []database.SoftwareStatementVerificationMethod `json:"software_statement_verification_methods"`
	RequireInitialAccessTokenCredentialTypes []database.AccountCredentialsType              `json:"require_initial_access_token_credential_types"`
	InitialAccessTokenGenerationMethods      []database.InitialAccessTokenGenerationMethod  `json:"initial_access_token_generation_methods"`
}

func (a *AccountDynamicRegistrationConfigDTO) ID() int32 {
	return a.id
}

func MapAccountDynamicRegistrationConfigToDTO(
	config *database.AccountDynamicRegistrationConfig,
) AccountDynamicRegistrationConfigDTO {
	return AccountDynamicRegistrationConfigDTO{
		id:                                       config.ID,
		CredentialsTypes:                         config.AccountCredentialsTypes,
		WhitelistedDomains:                       config.WhitelistedDomains,
		RequireSoftwareStatementCredentialTypes:  config.RequireSoftwareStatementCredentialTypes,
		SoftwareStatementVerificationMethods:     config.SoftwareStatementVerificationMethods,
		RequireInitialAccessTokenCredentialTypes: config.RequireInitialAccessTokenCredentialTypes,
		InitialAccessTokenGenerationMethods:      config.InitialAccessTokenGenerationMethods,
	}
}
