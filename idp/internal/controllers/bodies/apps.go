// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBodyBase struct {
	Type            string   `json:"type" validate:"required,oneof=web spa native backend device service mcp"`
	Name            string   `json:"name" validate:"required,min=3,max=50"`
	ClientURI       string   `json:"client_uri" validate:"required,url"`
	LogoURI         string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	TOSURI          string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI       string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	Contacts        []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	SoftwareID      string   `json:"software_id,omitempty" validate:"omitempty,max=250"`
	SoftwareVersion string   `json:"software_version,omitempty" validate:"omitempty,max=250"`
	Scopes          []string `json:"scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
	DefaultScopes   []string `json:"default_scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
}

type UpdateAppBodyBase struct {
	Name            string   `json:"name" validate:"required,max=50,min=3"`
	ClientURI       string   `json:"client_uri" validate:"required,url"`
	LogoURI         string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	TOSURI          string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI       string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	Contacts        []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	SoftwareID      string   `json:"software_id,omitempty" validate:"omitempty,max=250"`
	SoftwareVersion string   `json:"software_version,omitempty" validate:"omitempty,max=250"`
}

type CreateAppBodyWeb struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	Algorithm      string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	AuthMethods    string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins,omitempty" validate:"required_if=AuthMethods private_key_jwt,unique,dive,url"`
}

type UpdateAppBodyWeb struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins,omitempty" validate:"omitempty,unique,dive,url"`
}

type CreateAppBodySPA struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
}

type UpdateAppBodySPA struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
}

type CreateAppBodyNative struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURIs   []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
	LogoutURIs     []string `json:"logout_uris" validate:"required,unique,min=1,dive,uri"`
}

type UpdateAppBodyNative struct {
	UsernameColumn string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURIs   []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
	LogoutURIs     []string `json:"logout_uris" validate:"required,unique,min=1,dive,uri"`
}

type CreateAppBodyBackend struct {
	UsernameColumn   string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AuthMethods      string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
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
	AuthMethods      string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	Algorithm        string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	Issuers          []string `json:"issuers" validate:"required_if=AuthMethods private_key_jwt,unique,dive,url"`
	UsersAuthMethods string   `json:"users_auth_methods" validate:"required,oneof=client_secret_basic client_secret_post both_client_secrets private_key_jwt"`
	AllowedDomains   []string `json:"allowed_domains,omitempty" validate:"required_if=UsersAuthMethods private_key_jwt,unique,dive,fqdn"`
}

type UpdateAppBodyService struct {
	Issuers        []string `json:"issuers" validate:"required,unique,min=1,dive,url"`
	AllowedDomains []string `json:"allowed_domains,omitempty" validate:"omitempty,unique,dive,fqdn"`
}

type CreateAppBodyMCP struct {
	CallbackURIs  []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code 'code id_token'"`
}
