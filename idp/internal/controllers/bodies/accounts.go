// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type UpdateAccountBody struct {
	GivenName  string `json:"given_name" validate:"required,min=2,max=100"`
	FamilyName string `json:"family_name" validate:"required,min=2,max=100"`
}
