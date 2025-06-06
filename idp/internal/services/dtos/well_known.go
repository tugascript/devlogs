// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"fmt"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
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
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// Recommended
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// Optional
	ClaimsSupported []string `json:"claims_supported,omitempty"`
	// Optional
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
	// Optional
	GrantTypesSupported []string `json:"grant_types_supported,omitempty"`
}

var AuthMethodsSupported = []string{"client_secret_basic", "private_key_jwt"}
var ResponseTypesSupported = []string{"code", "id_token", "token", "id_token token"}
var SubjectTypesSupported = []string{"public", "pairwise"}
var CodeChallengeMethodsSupported = []string{"S256"}
var GrantTypesSupported = []string{"authorization_code", "refresh_token", "client_credentials"}

func MapOIDCConfigDTOToWellKnownOIDCConfigurationDTO(configDTO *OIDCConfigDTO, backendDomain, username string) WellKnownOIDCConfigurationDTO {
	baseURL := fmt.Sprintf("https://%s.%s", username, backendDomain)
	return WellKnownOIDCConfigurationDTO{
		Issuer:                            baseURL,
		AuthEndpoint:                      baseURL + paths.AppsOAuthBase + paths.AppsOAuthAuth,
		TokenEndpoint:                     baseURL + paths.AppsOAuthBase + paths.AppsOAuthToken,
		UserinfoEndpoint:                  baseURL + paths.AppsOAuthBase + paths.AppsOAuthUserinfo,
		RegistrationEndpoint:              baseURL + paths.AppsBase + paths.UsersBase + paths.AuthRegister,
		RevocationEndpoint:                baseURL + paths.AppsOAuthBase + paths.AppsOAuthRevoke,
		IntrospectionEndpoint:             baseURL + paths.AppsOAuthBase + paths.AppsOAuthIntrospect,
		DeviceAuthorizationEndpoint:       baseURL + paths.AppsOAuthBase + paths.AppsOAuthDeviceAuth,
		JWKsURI:                           baseURL + paths.WellKnownBase + paths.WellKnownJWKs,
		TokenEndpointAuthMethodsSupported: AuthMethodsSupported,
		ResponseTypesSupported:            ResponseTypesSupported,
		SubjectTypesSupported:             SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  []string{configDTO.JwtCryptoSuite},
		ScopesSupported:                   configDTO.Scopes,
		ClaimsSupported:                   configDTO.Claims,
		CodeChallengeMethodsSupported:     CodeChallengeMethodsSupported,
		GrantTypesSupported:               GrantTypesSupported,
	}
}
