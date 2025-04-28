// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type AccountCredentialsBody struct {
	Scopes []string `json:"scopes" validate:"required,unique,oneof=admin users:read users:write apps:read apps:write"`
	Alias  string   `json:"alias" validate:"required,min=1,max=50,alphanum"`
}
