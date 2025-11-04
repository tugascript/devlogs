// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package bodies

type OAuthDynamicClientRegistrationBody struct {
	RedirectURIs                 []string `json:"redirect_uris,omitempty" validate:"omitempty,min=1,dive,uri"`
	TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method,omitempty" validate:"omitempty,oneof=none client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	ResponseTypes                []string `json:"response_types,omitempty" validate:"omitempty,dive,oneof=code 'code id_token'"`
	GrantTypes                   []string `json:"grant_types,omitempty" validate:"omitempty,min=1,dive,oneof=authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:jwt-bearer"`
	ApplicationType              string   `json:"application_type" validate:"required,oneof=native service mcp web spa backend device"`
	ClientName                   string   `json:"client_name" validate:"required,min=1,max=255"`
	ClientURI                    string   `json:"client_uri" validate:"required,url"`
	LogoURI                      string   `json:"logo_uri,omitempty" validate:"omitempty,url"`
	Scope                        string   `json:"scope" validate:"required,multiple_scope"`
	Contacts                     []string `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	TOSURI                       string   `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI                    string   `json:"policy_uri,omitempty" validate:"omitempty,url"`
	JWKsURI                      string   `json:"jwks_uri,omitempty" validate:"omitempty,url"`
	JWKs                         []string `json:"jwks,omitempty" validate:"omitempty,json"`
	SoftwareID                   string   `json:"software_id,omitempty" validate:"omitempty,max=512"`
	SoftwareVersion              string   `json:"software_version,omitempty" validate:"omitempty,max=512"`
	SubjectType                  string   `json:"subject_type,omitempty" validate:"omitempty,oneof=public pairwise"`
	SectorIdentifierURI          string   `json:"sector_identifier_uri,omitempty" validate:"omitempty,url"`
	DefaultMaxAge                int64    `json:"default_max_age,omitempty" validate:"omitempty,min=0"`
	RequireAuthTime              bool     `json:"require_auth_time,omitempty" validate:"omitempty,bool"`
	DefaultACRValues             []string `json:"default_acr_values,omitempty" validate:"omitempty,unique,dive,max=100"`
	InitiateLoginURI             string   `json:"initiate_login_uri,omitempty" validate:"omitempty,url"`
	RequestURIs                  []string `json:"request_uris,omitempty" validate:"omitempty,unique,dive,url"`
	IDTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	IDTokenEncryptedResponseAlg  string   `json:"id_token_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	IDTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	UserInfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	UserInfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	UserInfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	RequestObjectSigningAlg      string   `json:"request_object_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	AccessTokenSigningAlg        string   `json:"access_token_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	SoftwareStatement            string   `json:"software_statement,omitempty" validate:"omitempty,jwt"`
}

type OAuthDynamicRegistrationIATAuthHiddenFieldsBody struct {
	CSRFToken           string `json:"csrf_token" validate:"required,min=21,base64rawurl"`
	ClientID            string `json:"client_id" validate:"required,fqdn"`
	ResponseType        string `json:"response_type" validate:"required,oneof=code"`
	CodeChallenge       string `json:"code_challenge" validate:"required,min=1"`
	CodeChallengeMethod string `json:"code_challenge_method" validate:"omitempty,oneof=plain s256 S256"`
	State               string `json:"state" validate:"required,min=1"`
	RedirectURI         string `json:"redirect_uri" validate:"required,uri"`
}

type OAuthDynamicRegistrationIATTokenBody struct {
	ClientID     string `json:"client_id" validate:"required,fqdn"`
	GrantType    string `json:"grant_type" validate:"required,eq=authorization_code"`
	Code         string `json:"code" validate:"required,min=1"`
	CodeVerifier string `json:"code_verifier" validate:"required,min=1"`
}

type OAuthDynamicRegistrationIATExtAppleUserBody struct {
	Email string `json:"email" validate:"required,email"`
}

type OAuthDynamicRegistrationIATExtAppleBody struct {
	Code  string `json:"code" validate:"required,min=1"`
	State string `json:"state" validate:"required,min=1"`
	User  string `json:"user" validate:"required,json"`
}
