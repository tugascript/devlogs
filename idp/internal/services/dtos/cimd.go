// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import "encoding/json"

// CIMDClientMetadata is the client metadata subset consumed by this IDP.
// Unknown JSON properties are ignored to allow metadata extensions.
type CIMDClientMetadata struct {
	ClientID                string          `json:"client_id"`
	ClientName              string          `json:"client_name"`
	ClientURI               string          `json:"client_uri,omitempty"`
	LogoURI                 string          `json:"logo_uri,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris,omitempty"`
	GrantTypes              []string        `json:"grant_types,omitempty"`
	ResponseTypes           []string        `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string          `json:"token_endpoint_auth_method,omitempty"`
	JWKSURI                 string          `json:"jwks_uri,omitempty"`
	JWKS                    json.RawMessage `json:"jwks,omitempty"`
}
