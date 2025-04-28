// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type OAuthURLParams struct {
	Provider string `validate:"oneof=apple facebook github google microsoft"`
}

type OAuthCallbackQueryParams struct {
	Code  string `validate:"required,min=1"`
	State string `validate:"required,min=1,hexadecimal"`
}
