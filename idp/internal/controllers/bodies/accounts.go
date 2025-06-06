// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type UpdateAccountBody struct {
	GivenName  string `json:"given_name" validate:"required,min=2,max=50"`
	FamilyName string `json:"family_name" validate:"required,min=2,max=50"`
	Username   string `json:"username" validate:"required,min=1,max=63,slug"`
}
