// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBodyBase struct {
	Type                  string   `json:"type" validate:"required,oneof=web spa native backend device service mcp"`
	Name                  string   `json:"name" validate:"required,min=3,max=50"`
	Domain                string   `json:"domain" validate:"omitempty,fqdn,max=250"`
	ClientURI             string   `json:"client_uri" validate:"required,url"`
	LogoURI               string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	TOSURI                string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI             string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	Contacts              []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	SoftwareID            string   `json:"software_id,omitempty" validate:"omitempty,max=250"`
	SoftwareVersion       string   `json:"software_version,omitempty" validate:"omitempty,max=250"`
	Scopes                []string `json:"scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
	DefaultScopes         []string `json:"default_scopes,omitempty" validate:"omitempty,unique,dive,single_scope"`
	AuthProviders         []string `json:"auth_providers,omitempty" validate:"omitempty,unique,dive,oneof=local apple facebook github google microsoft"`
	UsernameColumn        string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AllowUserRegistration bool     `json:"allow_user_registration,omitempty"`
}

type UpdateAppBodyBase struct {
	Name                  string   `json:"name" validate:"required,max=50,min=3"`
	Domain                string   `json:"domain" validate:"omitempty,fqdn,max=250"`
	ClientURI             string   `json:"client_uri" validate:"required,url"`
	LogoURI               string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	TOSURI                string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI             string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	Contacts              []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	SoftwareID            string   `json:"software_id,omitempty" validate:"omitempty,max=250"`
	SoftwareVersion       string   `json:"software_version,omitempty" validate:"omitempty,max=250"`
	AuthProviders         []string `json:"auth_providers,omitempty" validate:"omitempty,unique,dive,oneof=local apple facebook github google microsoft"`
	UsernameColumn        string   `json:"username_column,omitempty" validate:"omitempty,oneof=email username both"`
	AllowUserRegistration bool     `json:"allow_user_registration,omitempty"`
}

type CreateAppBodyWeb struct {
	Transport               string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	Algorithm               string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" validate:"required,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	ResponseTypes           []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs            []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
}

type UpdateAppBodyWeb struct {
	Transport     string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs  []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
}

type CreateAppBodySPA struct {
	Transport      string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
}

type UpdateAppBodySPA struct {
	Transport      string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	ResponseTypes  []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURLs   []string `json:"callback_urls" validate:"required,unique,min=1,dive,url"`
	LogoutURLs     []string `json:"logout_urls" validate:"required,unique,min=1,dive,url"`
	AllowedOrigins []string `json:"allowed_origins" validate:"required,unique,min=1,dive,url"`
}

type CreateAppBodyNative struct {
	Transport     string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURIs  []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
}

type UpdateAppBodyNative struct {
	Transport     string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	CallbackURIs  []string `json:"callback_uris" validate:"required,unique,min=1,dive,uri"`
}

type CreateAppBodyBackend struct {
	Transport   string `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	AuthMethods string `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	Algorithm   string `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	Domain      string `json:"domain" validate:"omitempty,fqdn"`
}

type UpdateAppBodyBackend struct {
	Transport string `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	Domain    string `json:"domain" validate:"omitempty,fqdn"`
}

type CreateAppBodyDevice struct {
	Transport      string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	AssociatedApps []string `json:"associated_apps,omitempty" validate:"omitempty,dive,min=22,max=22,alphanum"`
}

type UpdateAppBodyDevice struct {
	Transport      string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	AssociatedApps []string `json:"associated_apps,omitempty" validate:"omitempty,dive,min=22,max=22,alphanum"`
}

type CreateAppBodyService struct {
	Transport       string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	AuthMethods     string   `json:"auth_methods" validate:"required,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	Algorithm       string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	UsersAuthMethod string   `json:"users_auth_method" validate:"required,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	AllowedDomains  []string `json:"allowed_domains,omitempty" validate:"required_if=UsersAuthMethod private_key_jwt,unique,dive,fqdn"`
}

type UpdateAppBodyService struct {
	Transport      string   `json:"transport,omitempty" validate:"omitempty,oneof=http https"`
	AllowedDomains []string `json:"allowed_domains,omitempty" validate:"omitempty,unique,dive,fqdn,max=250"`
}

type CreateAppBodyMCP struct {
	Transport     string   `json:"transport" validate:"required,oneof=stdio streamable_http"`
	AuthMethod    string   `json:"auth_method,omitempty" validate:"required_if=Transport stdio,oneof=client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	Algorithm     string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code 'code id_token'"`
	CallbackURIs  []string `json:"callback_urls,omitempty" validate:"omitempty,unique,min=1,dive,uri"`
}

type UpdateAppBodyMCP struct {
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code 'code id_token'"`
	CallbackURIs  []string `json:"callback_urls,omitempty" validate:"omitempty,unique,min=1,dive,uri"`
}
