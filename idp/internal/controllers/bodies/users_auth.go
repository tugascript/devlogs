// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type RegisterUserBody struct {
	Email     string `json:"email" validate:"required,email"`
	Username  string `json:"username,omitempty" validate:"omitempty,slug,min=3,max=100"`
	Password  string `json:"password" validate:"required,min=8,max=63,password"`
	Password2 string `json:"password2" validate:"required,eqfield=Password"`
	UserData
}

type LoginUserBody struct {
	UsernameOrEmail string `json:"username_or_email" validate:"required,min=3,max=255"`
	Password        string `json:"password" validate:"required,min=1"`
}
