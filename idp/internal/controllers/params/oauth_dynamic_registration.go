// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type OAuthDynamicRegistrationIATAuthQueryParams struct {
	ClientID        string `validate:"required,fqdn"`
	ResponseType    string `validate:"required,oneof=code"`
	Challenge       string `validate:"required,min=1"`
	ChallengeMethod string `validate:"omitempty,oneof=plain s256 S256"`
	State           string `validate:"required,min=1"`
	RedirectURI     string `validate:"required,uri"`
}

type OAuthDynamicRegistrationIATAuthLoginGetQueryParams struct {
	Challenge       string `validate:"required,min=1"`
	ChallengeMethod string `validate:"omitempty,oneof=plain s256 S256"`
	RedirectURI     string `validate:"required,url"`
	State           string `validate:"required,min=1"`
}
