// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type Account2FAConfigBody struct {
	TwoFAType string `json:"two_factor_type" validate:"required,oneof=email totp"`
	IsDefault bool   `json:"is_default" validate:"required,boolean"`
}
