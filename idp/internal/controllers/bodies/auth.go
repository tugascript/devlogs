// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type RegisterAccountBody struct {
	Email      string `json:"email" validate:"required,email"`
	GivenName  string `json:"given_name" validate:"required,min=2,max=50"`
	FamilyName string `json:"family_name" validate:"required,min=2,max=50"`
	Username   string `json:"username,omitempty" validate:"omitempty,min=3,max=63,slug"`
	Password   string `json:"password" validate:"required,min=8,max=100,password"`
	Password2  string `json:"password2" validate:"required,eqfield=Password"`
}
