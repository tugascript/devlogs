// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

type OauthDynamicRegistrationOptions struct {
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	ResponseTypes           []string
	GrantTypes              []string
	ApplicationType         string
	ClientName              string
	ClientURI               string
	LogoURI                 string
	Scope                   string
	Contacts                []string
	TOSURI                  string
	PolicyURI               string
	JWKsURI                 string
	JWKs                    []string
	SoftwareID              string
	SoftwareVersion         string
}
