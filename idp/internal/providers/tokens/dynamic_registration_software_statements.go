// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const dynamicRegistrationSoftwareStatementsLocation = "dynamic_registration_software_statements"

type SoftwareStatementClaims struct {
	RedirectURIs                 []string      `json:"redirect_uris,omitempty" validate:"omitempty,min=1,dive,uri"`
	TokenEndpointAuthMethod      string        `json:"token_endpoint_auth_method,omitempty" validate:"omitempty,oneof=none client_secret_basic client_secret_post client_secret_jwt private_key_jwt"`
	GrantTypes                   []string      `json:"grant_types,omitempty" validate:"omitempty,min=1,dive,oneof=authorization_code refresh_token client_credentials urn:ietf:params:oauth:grant-type:jwt-bearer"`
	ResponseTypes                []string      `json:"response_types,omitempty" validate:"omitempty,dive,oneof=none code 'code id_token'"`
	ApplicationType              string        `json:"application_type,omitempty" validate:"omitempty,oneof=native service mcp"`
	ClientName                   string        `json:"client_name,omitempty" validate:"omitempty,min=1,max=255"`
	ClientURI                    string        `json:"client_uri,omitempty" validate:"omitempty,url"`
	LogoURI                      string        `json:"logo_uri,omitempty" validate:"omitempty,url"`
	Scope                        string        `json:"scope,omitempty" validate:"omitempty,multiple_scope"`
	Contacts                     []string      `json:"contacts,omitempty" validate:"omitempty,unique,dive,email"`
	TOSURI                       string        `json:"tos_uri,omitempty" validate:"omitempty,url"`
	PolicyURI                    string        `json:"policy_uri,omitempty" validate:"omitempty,url"`
	JWKsURI                      string        `json:"jwks_uri,omitempty" validate:"omitempty,url"`
	JWKs                         *utils.JWKSet `json:"jwks,omitempty" validate:"omitempty"`
	SoftwareID                   string        `json:"software_id,omitempty" validate:"omitempty,max=512"`
	SoftwareVersion              string        `json:"software_version,omitempty" validate:"omitempty,max=512"`
	SubjectType                  string        `json:"subject_type,omitempty" validate:"omitempty,oneof=public pairwise"`
	SectorIdentifierURI          string        `json:"sector_identifier_uri,omitempty" validate:"omitempty,url"`
	DefaultMaxAge                int64         `json:"default_max_age,omitempty" validate:"omitempty,min=0"`
	RequireAuthTime              bool          `json:"require_auth_time,omitempty" validate:"omitempty,bool"`
	DefaultACRValues             []string      `json:"default_acr_values,omitempty" validate:"omitempty,unique,dive,max=100"`
	InitiateLoginURI             string        `json:"initiate_login_uri,omitempty" validate:"omitempty,url"`
	RequestURIs                  []string      `json:"request_uris,omitempty" validate:"omitempty,unique,dive,url"`
	IDTokenSignedResponseAlg     string        `json:"id_token_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	IDTokenEncryptedResponseAlg  string        `json:"id_token_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	IDTokenEncryptedResponseEnc  string        `json:"id_token_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	UserInfoSignedResponseAlg    string        `json:"userinfo_signed_response_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	UserInfoEncryptedResponseAlg string        `json:"userinfo_encrypted_response_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	UserInfoEncryptedResponseEnc string        `json:"userinfo_encrypted_response_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	RequestObjectSigningAlg      string        `json:"request_object_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	RequestObjectEncryptionAlg   string        `json:"request_object_encryption_alg,omitempty" validate:"omitempty,oneof=RSA-OAEP-256 ECDH-ES ECDH-ES+A256KW"`
	RequestObjectEncryptionEnc   string        `json:"request_object_encryption_enc,omitempty" validate:"omitempty,oneof=A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM"`
	TokenEndpointAuthSigningAlg  string        `json:"token_endpoint_auth_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
	AccessTokenSigningAlg        string        `json:"access_token_signing_alg,omitempty" validate:"omitempty,oneof=RS256 ES256 EdDSA"`
}

type GetUnknownPublicJWK = func(kid string) (utils.JWK, error)

type softwareStatementJWTClaims struct {
	SoftwareStatementClaims
	jwt.RegisteredClaims
}

type VerifySoftwareStatementOptions struct {
	RequestID         string
	SoftwareStatement string
	GetPublicJWK      GetUnknownPublicJWK
}

func (t *Tokens) VerifySoftwareStatement(
	ctx context.Context,
	opts VerifySoftwareStatementOptions,
) (SoftwareStatementClaims, jwt.RegisteredClaims, error) {
	logger := utils.BuildLogger(t.logger, utils.LoggerOptions{
		Location:  dynamicRegistrationSoftwareStatementsLocation,
		Method:    "VerifySoftwareStatementToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying software statement token")

	var claims softwareStatementJWTClaims
	if _, err := jwt.ParseWithClaims(opts.SoftwareStatement, &claims, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			logger.DebugContext(ctx, "Failed to extract KID from software statement token", "error", err)
			return nil, err
		}

		jwk, err := opts.GetPublicJWK(kid)
		if err != nil {
			logger.WarnContext(ctx, "Failed to get public JWK for software statement token", "error", err, "kid", kid)
			return nil, err
		}

		return jwk.ToUsableKey()
	}); err != nil {
		logger.WarnContext(ctx, "Failed to verify software statement token", "error", err)
		return SoftwareStatementClaims{}, jwt.RegisteredClaims{}, err
	}

	return claims.SoftwareStatementClaims, claims.RegisteredClaims, nil
}
