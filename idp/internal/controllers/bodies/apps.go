// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBodyBase struct {
	Type      string `json:"type" validate:"required,oneof=web spa native backend device service"`
	Name      string `json:"name" validate:"required,max=50,min=3,alphanum"`
	ClientURI string `json:"client_uri" validate:"required,url"`
}

type CreateAppBodyWeb struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	Algorithm           string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	AuthMethods         string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,min=1,dive,url,unique"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,min=1,dive,url,unique"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty" validate:"omitempty,dive,url,unique"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" validate:"omitempty,oneof=S256 plain"`
}

type CreateAppBodySPA struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,min=1,dive,url,unique"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,min=1,dive,url,unique"`
	AllowedOrigins      []string `json:"allowed_origins" validate:"required,min=1,dive,url,unique"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type CreateAppBodyNative struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURIs        []string `json:"callback_uris" validate:"required,min=1,dive,uri,unique"`
	LogoutURIs          []string `json:"logout_uris" validate:"required,min=1,dive,uri,unique"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type CreateAppBodyBackend struct {
	UsernameColumn   string `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AuthMethods      string `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	Algorithm        string `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	ConfirmationURL  string `json:"confirmation_url" validate:"required,url"`
	ResetPasswordURL string `json:"reset_password_url" validate:"required,url"`
}

type CreateAppBodyDevice struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AssociatedApps []string `json:"associated_apps,omitempty" validate:"omitempty,dive,min=22,max=22,alphanum"`
}

type CreateAppBodyService struct {
	AuthMethods      string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	Algorithm        string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	UsersAuthMethods string   `json:"users_auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	AllowedDomains   []string `json:"allowed_domains,omitempty" validate:"required_id=AuthMethods private_key_jwt,dive,fqdn,unique"`
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
