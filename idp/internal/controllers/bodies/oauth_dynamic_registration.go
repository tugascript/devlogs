// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type OAuthDynamicClientRegistrationBody struct {
	RedirectURIs  []string `json:"redirect_uris" validate:"required,min=1,dive,uri"`
	ResponseTypes []string `json:"response_types" validate:"required,min=1,dive,oneof=code id_token 'code id_token'"`
}
