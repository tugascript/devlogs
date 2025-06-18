// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package paths

const (
	CredentialsBase string = "/credentials"

	CredentialsSingle string = "/:clientID"

	CredentialsSecrets string = "/:clientID/secrets"

	CredentialsSecretsSingle string = "/:clientID/secrets/:secretID"
)
