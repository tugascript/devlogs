// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"fmt"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type WellKnownOIDCConfigurationDTO struct {
	// Required
	Issuer string `json:"issuer"`
	// Required
	AuthEndpoint string `json:"authorization_endpoint"`
	// Required
	TokenEndpoint string `json:"token_endpoint"`
	// Recommended
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`
	// Recommended
	RegistrationEndpoint string `json:"registration_endpoint,omitempty"`
	// Recommended
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// Recommended
	IntrospectionEndpoint string `json:"introspection_endpoint,omitempty"`
	// Recommended
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint,omitempty"`

	// Required
	JWKsURI string `json:"jwks_uri"`

	// Optional
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	// Required
	ResponseTypesSupported []string `json:"response_types_supported"`
	// Required
	SubjectTypesSupported []string `json:"subject_types_supported"`
	// Required
	IDTokenSigningAlgValuesSupported []utils.SupportedCryptoSuite `json:"id_token_signing_alg_values_supported"`

	// Recommended
	ScopesSupported []database.Scopes `json:"scopes_supported,omitempty"`
	// Optional
	ClaimsSupported []database.Claims `json:"claims_supported,omitempty"`
	// Optional
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	// Optional
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
}

var AuthMethodsSupported = []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}
var ResponseTypesSupported = []string{"code", "id_token", "token", "id_token token"}
var SubjectTypesSupported = []string{"public", "pairwise"}
var CodeChallengeMethodsSupported = []string{"S256"}
var GrantTypesSupported = []string{
	"authorization_code",
	"refresh_token",
	"client_credentials",
	"urn:ietf:params:oauth:grant-type:device_code",
	"urn:ietf:params:oauth:grant-type:jwt-bearer",
}
var DefaultScopes = []database.Scopes{database.ScopesOpenid}

func MapOIDCConfigDTOToWellKnownOIDCConfigurationDTO(configDTO *OIDCConfigDTO, backendDomain, username string) WellKnownOIDCConfigurationDTO {
	baseURL := fmt.Sprintf("https://%s.%s", username, utils.ProcessURL(backendDomain))
	return WellKnownOIDCConfigurationDTO{
		Issuer:                            baseURL,
		AuthEndpoint:                      baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthAuth,
		TokenEndpoint:                     baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthToken,
		UserinfoEndpoint:                  baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthUserInfo,
		RegistrationEndpoint:              baseURL + paths.AppsBase + paths.UsersBase + paths.AuthRegister,
		RevocationEndpoint:                baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthRevoke,
		IntrospectionEndpoint:             baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthIntrospect,
		DeviceAuthorizationEndpoint:       baseURL + paths.AppsBase + paths.OAuthBase + paths.OAuthDeviceAuth,
		JWKsURI:                           baseURL + paths.WellKnownBase + paths.WellKnownJWKs,
		TokenEndpointAuthMethodsSupported: AuthMethodsSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  []utils.SupportedCryptoSuite{utils.SupportedCryptoSuiteES256},
		ScopesSupported:                   append(DefaultScopes, configDTO.ScopesSupported...),
		ClaimsSupported:                   configDTO.ClaimsSupported,
		CodeChallengeMethodsSupported:     CodeChallengeMethodsSupported,
		GrantTypesSupported:               GrantTypesSupported,
	}
}
