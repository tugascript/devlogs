// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type CredentialsURLParams struct {
	ClientID string `validate:"required,min=22,max=22,alphanum"`
}

type CredentialsSecretOrKeyURLParams struct {
	ClientID string `validate:"required,min=22,max=22,alphanum"`
	SecretID string `validate:"omitempty,min=22,max=26,secret_or_key"`
}
