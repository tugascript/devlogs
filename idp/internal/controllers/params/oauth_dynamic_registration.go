// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type OAuthDynamicRegistrationIATAuthBaseQueryParams struct {
	ClientID    string `validate:"required,fqdn"`
	RedirectURI string `validate:"required,uri"`
}

type OAuthDynamicRegistrationIATAuthQueryParams struct {
	ResponseType    string `validate:"required,oneof=code"`
	Challenge       string `validate:"required,min=1"`
	ChallengeMethod string `validate:"omitempty,oneof=plain s256 S256"`
	State           string `validate:"required,min=1"`
}

type OAuthDynamicRegistrationIATAuthURLParams struct {
	ACCClientID string `validate:"required,min=22,max=22,alphanum"`
}

type OAuthDynamicRegistrationIATExtAuthURLParams struct {
	ACCClientID string `validate:"required,min=22,max=22,alphanum"`
	Provider    string `validate:"required,oneof=facebook github google microsoft"`
}

type OAuthDynamicRegistrationIATExtAppleURLParams struct {
	ACCClientID string `validate:"required,min=22,max=22,alphanum"`
}
