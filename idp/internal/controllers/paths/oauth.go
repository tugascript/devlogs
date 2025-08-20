// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package paths

const (
	OAuthBase string = "/oauth2"

	OAuthKeys       string = "/jwks"
	OAuthAuth       string = "/auth"
	OAuthUserInfo   string = "/userinfo"
	OAuthToken      string = "/token"
	OAuthRevoke     string = "/revoke"
	OAuthRegister   string = "/register"
	OAuthIntrospect string = "/introspect"
	OAuthDeviceAuth string = "/auth/device"

	OAuthAppleCallback string = "/apple/callback"
	OAuthCallback      string = "/:provider/callback"
)
