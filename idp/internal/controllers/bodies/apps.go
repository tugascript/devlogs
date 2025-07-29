// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBodyBase struct {
	Type      string `json:"type" validate:"required,oneof=web spa native backend device service"`
	Name      string `json:"name" validate:"required,min=3,max=50"`
	ClientURI string `json:"client_uri" validate:"required,url"`
}

type UpdateAppBodyBase struct {
	Name            string `json:"name" validate:"required,max=50,min=3"`
	ClientURI       string `json:"client_uri" validate:"required,url"`
	LogoURI         string `json:"logo_uri,omitempty" validate:"omitempty,url"`
	TOSURI          string `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI       string `json:"policy_uri,omitempty" validate:"omitempty,url"`
	SoftwareID      string `json:"software_id,omitempty" validate:"omitempty,alphanum"`
	SoftwareVersion string `json:"software_version,omitempty" validate:"omitempty,alphanum"`
}

type CreateAppBodyWeb struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	Algorithm           string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	AuthMethods         string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty" validate:"omitempty,unique,dive,url"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" validate:"omitempty,oneof=S256 plain"`
}

type UpdateAppBodyWeb struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,min=1,dive,url,unique"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,min=1,dive,url,unique"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty" validate:"omitempty,dive,url,unique"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty" validate:"omitempty,oneof=S256 plain"`
}

type CreateAppBodySPA struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins      []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type UpdateAppBodySPA struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURLs        []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs          []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins      []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type CreateAppBodyNative struct {
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURIs        []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
	LogoutURIs          []string `json:"logout_uris" validate:"required,unique,min=1,dive,uri"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type UpdateAppBodyNative struct {
	Name                string   `json:"name" validate:"required,max=50,min=3,alphanum"`
	UsernameColumn      string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	CallbackURIs        []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
	LogoutURIs          []string `json:"logout_uris" validate:"required,unique,min=1,dive,uri"`
	CodeChallengeMethod string   `json:"code_challenge_method" validate:"required,oneof=S256 plain"`
}

type CreateAppBodyBackend struct {
	UsernameColumn   string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	Algorithm        string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	Issuers          []string `json:"issuers" validate:"required,unique,min=1,dive,url"`
	ConfirmationURL  string   `json:"confirmation_url" validate:"required,url"`
	ResetPasswordURL string   `json:"reset_password_url" validate:"required,url"`
}

type UpdateAppBodyBackend struct {
	UsernameColumn   string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	Issuers          []string `json:"issuers" validate:"required,unique,min=1,dive,url"`
	ConfirmationURL  string   `json:"confirmation_url" validate:"required,url"`
	ResetPasswordURL string   `json:"reset_password_url" validate:"required,url"`
}

type CreateAppBodyDevice struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AssociatedApps []string `json:"associated_apps,omitempty" validate:"omitempty,dive,min=22,max=22,alphanum"`
}

type UpdateAppBodyDevice struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AssociatedApps []string `json:"associated_apps,omitempty" validate:"omitempty,dive,min=22,max=22,alphanum"`
}

type CreateAppBodyService struct {
	Algorithm        string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	Issuers          []string `json:"issuers" validate:"required,unique,min=1,dive,url"`
	UsersAuthMethods string   `json:"users_auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	AllowedDomains   []string `json:"allowed_domains,omitempty" validate:"required_if=AuthMethods private_key_jwt,unique,dive,fqdn"`
}

type UpdateAppBodyService struct {
	Issuers        []string `json:"issuers" validate:"required,unique,min=1,dive,url"`
	AllowedDomains []string `json:"allowed_domains,omitempty" validate:"omitempty,unique,dive,fqdn"`
}
