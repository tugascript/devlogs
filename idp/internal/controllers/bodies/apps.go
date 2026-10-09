// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type CreateAppBodyBase struct {
	Type                  string   `json:"type" validate:"required,oneof=web native"`
	Name                  string   `json:"name" validate:"required,min=1,max=255"`
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
	Name                  string   `json:"name" validate:"required,max=255,min=1"`
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
	Algorithm               string   `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method" validate:"required,oneof=none client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	GrantTypes              []string `json:"grant_types,omitempty" validate:"omitempty,unique,dive,oneof=authorization_code implicit refresh_token client_credentials urn:ietf:params:oauth:grant-type:jwt-bearer urn:ietf:params:oauth:grant-type:device_code"`
	ResponseTypes           []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	RedirectURIs            []string `json:"redirect_uris,omitempty" validate:"omitempty,unique,dive,url"`
}

type UpdateAppBodyWeb struct {
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	RedirectURIs  []string `json:"redirect_uris,omitempty" validate:"omitempty,unique,dive,url"`
}

type CreateAppBodyNative struct {
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	RedirectURIs  []string `json:"redirect_uris" validate:"required,unique,min=1,dive,uri"`
}

type UpdateAppBodyNative struct {
	ResponseTypes []string `json:"response_types,omitempty" validate:"omitempty,unique,dive,oneof=code id_token 'code id_token'"`
	RedirectURIs  []string `json:"redirect_uris" validate:"required,unique,min=1,dive,uri"`
}
