// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBody struct {
	Name           string `json:"name" validate:"required,max=50,min=3,alphanum"`
	Type           string `json:"type" validate:"required,oneof=web mobile spa desktop all"`
	UsernameColumn string `json:"username_column" validate:"required,oneof=email username both"`
}

type UpdateAppBody struct {
	Name            string   `json:"name" validate:"required,max=50,min=3,alphanum"`
	DefaultScopes   []string `json:"default_scopes" validate:"required,oneof=openid email profile address phone"`
	CallbackURIs    []string `json:"callback_uris" validate:"required,url"`
	LogoutURIs      []string `json:"logout_uris" validate:"required,url"`
	Providers       []string `json:"providers" validate:"required,oneof=email_password client_credentials github google facebook apple microsoft"`
	IDTokenTTL      int32    `json:"id_token_ttl" validate:"required,gte=30,lte=2592000"` // 30 secs to 30 days
	UsernameColumn  string   `json:"username_column" validate:"required,oneof=email username both"`
	ConfirmationURI string   `json:"confirmation_uri" validate:"required,url"`
	ResetURI        string   `json:"reset_uri" validate:"required,url"`
}
