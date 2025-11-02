// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type ApplicationRegistrationData struct {
	RedirectURIs                 []string
	TokenEndpointAuthMethod      string
	ResponseTypes                []string
	GrantTypes                   []string
	ApplicationType              string
	ClientName                   string
	ClientURI                    string
	LogoURI                      string
	Scope                        string
	Contacts                     []string
	TOSURI                       string
	PolicyURI                    string
	JWKsURI                      string
	JWKs                         []string
	SoftwareID                   string
	SoftwareVersion              string
	SubjectType                  string
	SectorIdentifierURI          string
	DefaultMaxAge                int64
	RequireAuthTime              bool
	DefaultACRValues             []string
	InitiateLoginURI             string
	RequestURIs                  []string
	IDTokenSignedResponseAlg     string
	IDTokenEncryptedResponseAlg  string
	IDTokenEncryptedResponseEnc  string
	UserInfoSignedResponseAlg    string
	UserInfoEncryptedResponseAlg string
	UserInfoEncryptedResponseEnc string
	RequestObjectSigningAlg      string
	RequestObjectEncryptionAlg   string
	RequestObjectEncryptionEnc   string
	TokenEndpointAuthSigningAlg  string
	AccessTokenSigningAlg        string
}

type verifySoftwareStatementSTDClaimsOptions struct {
	requestID      string
	backendDomain  string
	frontendDomain string
	domain         string
	baseDomain     string
	claims         *jwt.RegisteredClaims
}

func (s *Services) verifySoftwareStatementSTDClaims(
	ctx context.Context,
	opts verifySoftwareStatementSTDClaimsOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, accountCredentialsRegistrationLocation, "verifySoftwareStatementSTDClaims").With(
		"domain", opts.domain,
		"baseDomain", opts.baseDomain,
	)
	logger.InfoContext(ctx, "Verifying software statement standard claims")

	if opts.claims.Issuer != fmt.Sprintf("https://%s", opts.baseDomain) &&
		opts.claims.Issuer != fmt.Sprintf("https://%s", opts.domain) {
		logger.WarnContext(ctx, "Software statement issuer does not match client URI domain or base domain",
			"issuer", opts.claims.Issuer,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.Audience == nil || !slices.ContainsFunc(opts.claims.Audience, func(aud string) bool {
		return aud == fmt.Sprintf("https://%s", opts.frontendDomain) || aud == fmt.Sprintf("https://%s", opts.backendDomain)
	}) {
		logger.WarnContext(ctx, "Software statement audience does not match frontend or backend domain",
			"audience", opts.claims.Audience,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.IssuedAt == nil || opts.claims.IssuedAt.Time.IsZero() || opts.claims.IssuedAt.Time.After(time.Now()) {
		logger.WarnContext(ctx, "Software statement issued at claim is invalid",
			"issuedAt", opts.claims.IssuedAt,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.NotBefore != nil && !opts.claims.NotBefore.Time.IsZero() && opts.claims.NotBefore.Time.After(time.Now()) {
		logger.WarnContext(ctx, "Software statement not before claim is invalid",
			"notBefore", opts.claims.NotBefore,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.ExpiresAt == nil || opts.claims.ExpiresAt.Time.IsZero() || opts.claims.ExpiresAt.Time.Before(time.Now()) {
		logger.WarnContext(ctx, "Software statement expiration claim is invalid",
			"expiresAt", opts.claims.ExpiresAt,
		)
		return exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Verified software statement standard claims")
	return nil
}

type verifySoftwareStatementClaimsOptions struct {
	requestID       string
	clientName      string
	clientURI       string
	logoURI         string
	tosURI          string
	policyURI       string
	contacts        []string
	softwareID      string
	softwareVersion string
	jwksURI         string
	jwks            []string
	claims          *tokens.SoftwareStatementClaims
}

func (s *Services) verifySoftwareStatementClaims(
	ctx context.Context,
	opts verifySoftwareStatementClaimsOptions,
) error {
	logger := s.buildLogger(
		opts.requestID,
		accountCredentialsRegistrationLocation,
		"verifySoftwareStatementClaims",
	)

	if opts.claims.ClientName != opts.clientName {
		logger.WarnContext(ctx, "Client name in software statement does not match",
			"expected", opts.clientName, "got", opts.claims.ClientName,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.ClientURI != opts.clientURI {
		logger.WarnContext(ctx, "Client URI in software statement does not match",
			"expected", opts.clientURI, "got", opts.claims.ClientURI,
		)
		return exceptions.NewUnauthorizedError()
	}

	if opts.claims.LogoURI != "" && opts.logoURI != "" && opts.claims.LogoURI != opts.logoURI {
		logger.WarnContext(ctx, "Logo URI in software statement does not match",
			"expected", opts.logoURI, "got", opts.claims.LogoURI,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.TOSURI != "" && opts.tosURI != "" && opts.claims.TOSURI != opts.tosURI {
		logger.WarnContext(ctx, "Terms of Service URI in software statement does not match",
			"expected", opts.tosURI, "got", opts.claims.TOSURI,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.PolicyURI != "" && opts.policyURI != "" && opts.claims.PolicyURI != opts.policyURI {
		logger.WarnContext(ctx, "Policy URI in software statement does not match",
			"expected", opts.policyURI, "got", opts.claims.PolicyURI,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.SoftwareID != "" && opts.softwareID != "" && opts.claims.SoftwareID != opts.softwareID {
		logger.WarnContext(ctx, "Software id in software statement does not match",
			"expected", opts.softwareID, "got", opts.claims.SoftwareID,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.SoftwareVersion != "" && opts.softwareVersion != "" && opts.claims.SoftwareVersion != opts.softwareVersion {
		logger.WarnContext(ctx, "Software version in software statement does not match",
			"expected", opts.softwareVersion, "got", opts.claims.SoftwareVersion,
		)
		return exceptions.NewUnauthorizedError()
	}
	if opts.claims.JWKsURI != "" && opts.jwksURI != "" && opts.claims.JWKsURI != opts.jwksURI {
		logger.WarnContext(ctx, "JWKs URI in software statement does not match", "expected",
			opts.jwksURI, "got", opts.claims.JWKsURI,
		)
		return exceptions.NewUnauthorizedError()
	}

	if len(opts.claims.Contacts) > 0 && len(opts.contacts) > 0 {
		claimsSet := utils.SliceToHashSet(opts.claims.Contacts)
		for _, c := range opts.contacts {
			if !claimsSet.Contains(c) {
				logger.WarnContext(ctx, "Contact in registration not present in software statement", "contact", c)
				return exceptions.NewUnauthorizedError()
			}
		}
	}

	logger.InfoContext(ctx, "Verified software statement registration claims")
	return nil
}

// validateEncryptionAlgorithmPair validates that encryption algorithm and encoding are both set or both unset
func validateEncryptionAlgorithmPair(alg, enc string) bool {
	if enc != "" && alg == "" {
		return false
	}

	return true
}

type validateSoftwareStatementClaimsOptions struct {
	requestID     string
	claims        *tokens.SoftwareStatementClaims
	data          *ApplicationRegistrationData
	allowedScopes utils.HashSet[string]
}

func (s *Services) validateSoftwareStatementClaims(
	ctx context.Context,
	opts validateSoftwareStatementClaimsOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(
		opts.requestID,
		accountCredentialsRegistrationLocation,
		"validateSoftwareStatementClaims",
	)
	logger.InfoContext(ctx, "Validating software statement claims")

	if err := s.validate.StructCtx(ctx, opts.claims); err != nil {
		logger.WarnContext(ctx, "Invalid software statement claims", "error", err)
		return exceptions.NewValidationError("Invalid software statement claims")
	}

	if opts.claims.Scope != "" {
		scopes := strings.Fields(opts.claims.Scope)
		if len(scopes) == 0 {
			logger.WarnContext(ctx, "Invalid scope format in software statement")
			return exceptions.NewValidationError("invalid scope")
		}
		for _, scope := range scopes {
			if !opts.allowedScopes.Contains(scope) {
				logger.WarnContext(ctx, "Invalid scope in software statement", "scope", scope)
				return exceptions.NewValidationError("invalid scope")
			}
		}

		scopesSet := utils.SliceToHashSet(scopes)
		if scopesSet.Size() != len(scopes) {
			logger.WarnContext(ctx, "Duplicate scopes in software statement", "scopes", scopes)
			return exceptions.NewValidationError("duplicate scopes")
		}

		dataScopes := strings.Fields(opts.data.Scope)
		if len(dataScopes) != scopesSet.Size() {
			logger.WarnContext(ctx, "Scope count mismatch", "expected", len(dataScopes), "got", scopesSet.Size())
			return exceptions.NewValidationError("scope count mismatch")
		}

		for _, scope := range dataScopes {
			if !scopesSet.Contains(scope) {
				logger.WarnContext(ctx, "Scope mismatch", "expected", scope, "got", scopesSet.Contains(scope))
				return exceptions.NewValidationError("scope mismatch")
			}
		}
	}

	if len(opts.claims.JWKs) > 0 {
		jwks := make([]utils.JWK, len(opts.claims.JWKs))
		indexMap := make(map[string]int)
		for i, rawJWK := range opts.claims.JWKs {
			jwk, err := utils.JsonToJWK([]byte(rawJWK))
			if err != nil {
				logger.WarnContext(ctx, "Invalid JWK JSON in software statement", "error", err)
				return exceptions.NewValidationError("invalid jwks")
			}
			jwks[i] = jwk
			indexMap[jwk.GetKeyID()] = i
		}

		if len(opts.data.JWKs) > 0 {
			if len(jwks) != len(opts.data.JWKs) {
				logger.WarnContext(ctx, "JWK count mismatch", "expected", len(opts.data.JWKs), "got", len(jwks))
				return exceptions.NewValidationError("jwk count mismatch")
			}

			for _, rawJWK := range opts.data.JWKs {
				jwk, err := utils.JsonToJWK([]byte(rawJWK))
				if err != nil {
					logger.WarnContext(ctx, "Invalid JWK JSON in software statement", "error", err)
					return exceptions.NewValidationError("invalid jwks")
				}

				index, ok := indexMap[jwk.GetKeyID()]
				if !ok {
					logger.WarnContext(ctx, "JWK not found in software statement", "jwk", jwk.GetKeyID())
					return exceptions.NewValidationError("jwk not found in software statement")
				}
				if jwks[index].ComparePublicKey(jwk) {
					logger.WarnContext(ctx, "JWK mismatch", "expected", jwks[index].GetKeyID(), "got", jwk.GetKeyID())
					return exceptions.NewValidationError("jwk mismatch")
				}
			}
		}
	}

	if !validateEncryptionAlgorithmPair(opts.claims.IDTokenEncryptedResponseAlg, opts.claims.IDTokenEncryptedResponseEnc) {
		logger.WarnContext(ctx, "id_token encryption algorithm and encoding must both be set or both be unset")
		return exceptions.NewValidationError("id_token encryption algorithm and encoding mismatch")
	}

	if !validateEncryptionAlgorithmPair(opts.claims.UserInfoEncryptedResponseAlg, opts.claims.UserInfoEncryptedResponseEnc) {
		logger.WarnContext(ctx, "userinfo encryption algorithm and encoding must both be set or both be unset")
		return exceptions.NewValidationError("userinfo encryption algorithm and encoding mismatch")
	}

	if !validateEncryptionAlgorithmPair(opts.claims.RequestObjectEncryptionAlg, opts.claims.RequestObjectEncryptionEnc) {
		logger.WarnContext(ctx, "request_object encryption algorithm and encoding must both be set or both be unset")
		return exceptions.NewValidationError("request_object encryption algorithm and encoding mismatch")
	}

	if len(opts.data.RedirectURIs) > 0 && len(opts.claims.RedirectURIs) > 0 {
		if len(opts.data.RedirectURIs) != len(opts.claims.RedirectURIs) {
			logger.WarnContext(ctx, "Redirect URI count mismatch", "expected", len(opts.data.RedirectURIs), "got", len(opts.claims.RedirectURIs))
			return exceptions.NewValidationError("redirect URI count mismatch")
		}

		redirectURIsSet := utils.SliceToHashSet(opts.claims.RedirectURIs)
		if redirectURIsSet.Size() != len(opts.claims.RedirectURIs) {
			logger.WarnContext(ctx, "Duplicate redirect URIs in software statement", "redirectURIs", opts.claims.RedirectURIs)
			return exceptions.NewValidationError("duplicate redirect URIs")
		}

		for _, redirectURI := range opts.data.RedirectURIs {
			if !redirectURIsSet.Contains(redirectURI) {
				logger.WarnContext(ctx, "Redirect URI not found in software statement", "redirectURI", redirectURI)
				return exceptions.NewValidationError("redirect URI not found in software statement")
			}
		}
	}

	if opts.claims.TokenEndpointAuthMethod != "" && opts.data.TokenEndpointAuthMethod != "" && opts.claims.TokenEndpointAuthMethod != opts.data.TokenEndpointAuthMethod {
		logger.WarnContext(ctx, "Token endpoint auth method mismatch", "expected", opts.data.TokenEndpointAuthMethod, "got", opts.claims.TokenEndpointAuthMethod)
		return exceptions.NewValidationError("token endpoint auth method mismatch")
	}

	if len(opts.claims.ResponseTypes) > 0 && len(opts.data.ResponseTypes) > 0 {
		if len(opts.claims.ResponseTypes) != len(opts.data.ResponseTypes) {
			logger.WarnContext(ctx, "Response type count mismatch", "expected", len(opts.data.ResponseTypes), "got", len(opts.claims.ResponseTypes))
			return exceptions.NewValidationError("response type count mismatch")
		}

		responseTypesSet := utils.SliceToHashSet(opts.claims.ResponseTypes)
		if responseTypesSet.Size() != len(opts.claims.ResponseTypes) {
			logger.WarnContext(ctx, "Duplicate response types in software statement", "responseTypes", opts.claims.ResponseTypes)
			return exceptions.NewValidationError("duplicate response types")
		}

		for _, responseType := range opts.data.ResponseTypes {
			if !responseTypesSet.Contains(responseType) {
				logger.WarnContext(ctx, "Response type not found in software statement", "responseType", responseType)
				return exceptions.NewValidationError("response type not found in software statement")
			}
		}
	}

	if len(opts.claims.GrantTypes) > 0 && len(opts.data.GrantTypes) > 0 {
		if len(opts.claims.GrantTypes) != len(opts.data.GrantTypes) {
			logger.WarnContext(ctx, "Grant type count mismatch", "expected", len(opts.data.GrantTypes), "got", len(opts.claims.GrantTypes))
			return exceptions.NewValidationError("grant type count mismatch")
		}

		grantTypesSet := utils.SliceToHashSet(opts.claims.GrantTypes)
		if grantTypesSet.Size() != len(opts.claims.GrantTypes) {
			logger.WarnContext(ctx, "Duplicate grant types in software statement", "grantTypes", opts.claims.GrantTypes)
			return exceptions.NewValidationError("duplicate grant types")
		}

		for _, grantType := range opts.data.GrantTypes {
			if !grantTypesSet.Contains(grantType) {
				logger.WarnContext(ctx, "Grant type not found in software statement", "grantType", grantType)
				return exceptions.NewValidationError("grant type not found in software statement")
			}
		}
	}

	if opts.claims.ApplicationType != "" && opts.data.ApplicationType != "" && opts.claims.ApplicationType != opts.data.ApplicationType {
		logger.WarnContext(ctx, "Application type mismatch", "expected", opts.data.ApplicationType, "got", opts.claims.ApplicationType)
		return exceptions.NewValidationError("application type mismatch")
	}
	if opts.claims.ClientName != "" && opts.data.ClientName != "" && opts.claims.ClientName != opts.data.ClientName {
		logger.WarnContext(ctx, "Client name mismatch", "expected", opts.data.ClientName, "got", opts.claims.ClientName)
		return exceptions.NewValidationError("client name mismatch")
	}
	if opts.claims.ClientURI != "" && opts.data.ClientURI != "" && opts.claims.ClientURI != opts.data.ClientURI {
		logger.WarnContext(ctx, "Client URI mismatch", "expected", opts.data.ClientURI, "got", opts.claims.ClientURI)
		return exceptions.NewValidationError("client URI mismatch")
	}
	if opts.claims.LogoURI != "" && opts.data.LogoURI != "" && opts.claims.LogoURI != opts.data.LogoURI {
		logger.WarnContext(ctx, "Logo URI mismatch", "expected", opts.data.LogoURI, "got", opts.claims.LogoURI)
		return exceptions.NewValidationError("logo URI mismatch")
	}
	if opts.claims.TOSURI != "" && opts.data.TOSURI != "" && opts.claims.TOSURI != opts.data.TOSURI {
		logger.WarnContext(ctx, "Terms of Service URI mismatch", "expected", opts.data.TOSURI, "got", opts.claims.TOSURI)
		return exceptions.NewValidationError("terms of service URI mismatch")
	}
	if opts.claims.PolicyURI != "" && opts.data.PolicyURI != "" && opts.claims.PolicyURI != opts.data.PolicyURI {
		logger.WarnContext(ctx, "Policy URI mismatch", "expected", opts.data.PolicyURI, "got", opts.claims.PolicyURI)
		return exceptions.NewValidationError("policy URI mismatch")
	}
	if opts.claims.SoftwareID != "" && opts.data.SoftwareID != "" && opts.claims.SoftwareID != opts.data.SoftwareID {
		logger.WarnContext(ctx, "Software ID mismatch", "expected", opts.data.SoftwareID, "got", opts.claims.SoftwareID)
		return exceptions.NewValidationError("software ID mismatch")
	}
	if opts.claims.SoftwareVersion != "" && opts.data.SoftwareVersion != "" && opts.claims.SoftwareVersion != opts.data.SoftwareVersion {
		logger.WarnContext(ctx, "Software version mismatch", "expected", opts.data.SoftwareVersion, "got", opts.claims.SoftwareVersion)
		return exceptions.NewValidationError("software version mismatch")
	}
	if opts.claims.SubjectType != "" && opts.data.SubjectType != "" && opts.claims.SubjectType != opts.data.SubjectType {
		logger.WarnContext(ctx, "Subject type mismatch", "expected", opts.data.SubjectType, "got", opts.claims.SubjectType)
		return exceptions.NewValidationError("subject type mismatch")
	}
	if opts.claims.SectorIdentifierURI != "" && opts.data.SectorIdentifierURI != "" && opts.claims.SectorIdentifierURI != opts.data.SectorIdentifierURI {
		logger.WarnContext(ctx, "Sector identifier URI mismatch", "expected", opts.data.SectorIdentifierURI, "got", opts.claims.SectorIdentifierURI)
		return exceptions.NewValidationError("sector identifier URI mismatch")
	}
	if opts.claims.DefaultMaxAge != 0 && opts.data.DefaultMaxAge != 0 && opts.claims.DefaultMaxAge != opts.data.DefaultMaxAge {
		logger.WarnContext(ctx, "Default max age mismatch", "expected", opts.data.DefaultMaxAge, "got", opts.claims.DefaultMaxAge)
		return exceptions.NewValidationError("default max age mismatch")
	}
	if opts.claims.RequireAuthTime != false && opts.data.RequireAuthTime != false && opts.claims.RequireAuthTime != opts.data.RequireAuthTime {
		logger.WarnContext(ctx, "Require auth time mismatch", "expected", opts.data.RequireAuthTime, "got", opts.claims.RequireAuthTime)
		return exceptions.NewValidationError("require auth time mismatch")
	}
	if len(opts.claims.DefaultACRValues) > 0 && len(opts.data.DefaultACRValues) > 0 {
		if len(opts.claims.DefaultACRValues) != len(opts.data.DefaultACRValues) {
			logger.WarnContext(ctx, "Default ACR value count mismatch", "expected", len(opts.data.DefaultACRValues), "got", len(opts.claims.DefaultACRValues))
			return exceptions.NewValidationError("default ACR value count mismatch")
		}
		defaultACRValuesSet := utils.SliceToHashSet(opts.claims.DefaultACRValues)
		if defaultACRValuesSet.Size() != len(opts.claims.DefaultACRValues) {
			logger.WarnContext(ctx, "Duplicate default ACR values in software statement", "defaultACRValues", opts.claims.DefaultACRValues)
			return exceptions.NewValidationError("duplicate default ACR values")
		}
		for _, defaultACRValue := range opts.data.DefaultACRValues {
			if !defaultACRValuesSet.Contains(defaultACRValue) {
				logger.WarnContext(ctx, "Default ACR value not found in software statement", "defaultACRValue", defaultACRValue)
				return exceptions.NewValidationError("default ACR value not found in software statement")
			}
		}
	}
	if opts.claims.InitiateLoginURI != "" && opts.data.InitiateLoginURI != "" && opts.claims.InitiateLoginURI != opts.data.InitiateLoginURI {
		logger.WarnContext(ctx, "Initiate login URI mismatch", "expected", opts.data.InitiateLoginURI, "got", opts.claims.InitiateLoginURI)
		return exceptions.NewValidationError("initiate login URI mismatch")
	}
	if len(opts.claims.RequestURIs) > 0 && len(opts.data.RequestURIs) > 0 {
		if len(opts.claims.RequestURIs) != len(opts.data.RequestURIs) {
			logger.WarnContext(ctx, "Request URI count mismatch", "expected", len(opts.data.RequestURIs), "got", len(opts.claims.RequestURIs))
			return exceptions.NewValidationError("request URI count mismatch")
		}

		requestURIsSet := utils.SliceToHashSet(opts.claims.RequestURIs)
		if requestURIsSet.Size() != len(opts.claims.RequestURIs) {
			logger.WarnContext(ctx, "Duplicate request URIs in software statement", "requestURIs", opts.claims.RequestURIs)
			return exceptions.NewValidationError("duplicate request URIs")
		}
		for _, requestURI := range opts.data.RequestURIs {
			if !requestURIsSet.Contains(requestURI) {
				logger.WarnContext(ctx, "Request URI not found in software statement", "requestURI", requestURI)
				return exceptions.NewValidationError("request URI not found in software statement")
			}
		}
	}
	if opts.claims.IDTokenSignedResponseAlg != "" && opts.data.IDTokenSignedResponseAlg != "" && opts.claims.IDTokenSignedResponseAlg != opts.data.IDTokenSignedResponseAlg {
		logger.WarnContext(ctx, "ID token signed response algorithm mismatch", "expected", opts.data.IDTokenSignedResponseAlg, "got", opts.claims.IDTokenSignedResponseAlg)
		return exceptions.NewValidationError("id token signed response algorithm mismatch")
	}
	if opts.claims.IDTokenEncryptedResponseAlg != "" && opts.data.IDTokenEncryptedResponseAlg != "" && opts.claims.IDTokenEncryptedResponseAlg != opts.data.IDTokenEncryptedResponseAlg {
		logger.WarnContext(ctx, "ID token encrypted response algorithm mismatch", "expected", opts.data.IDTokenEncryptedResponseAlg, "got", opts.claims.IDTokenEncryptedResponseAlg)
		return exceptions.NewValidationError("id token encrypted response algorithm mismatch")
	}
	if opts.claims.IDTokenEncryptedResponseEnc != "" && opts.data.IDTokenEncryptedResponseEnc != "" && opts.claims.IDTokenEncryptedResponseEnc != opts.data.IDTokenEncryptedResponseEnc {
		logger.WarnContext(ctx, "ID token encrypted response encoding mismatch", "expected", opts.data.IDTokenEncryptedResponseEnc, "got", opts.claims.IDTokenEncryptedResponseEnc)
		return exceptions.NewValidationError("id token encrypted response encoding mismatch")
	}
	if opts.claims.UserInfoSignedResponseAlg != "" && opts.data.UserInfoSignedResponseAlg != "" && opts.claims.UserInfoSignedResponseAlg != opts.data.UserInfoSignedResponseAlg {
		logger.WarnContext(ctx, "User info signed response algorithm mismatch", "expected", opts.data.UserInfoSignedResponseAlg, "got", opts.claims.UserInfoSignedResponseAlg)
		return exceptions.NewValidationError("user info signed response algorithm mismatch")
	}
	if opts.claims.UserInfoEncryptedResponseAlg != "" && opts.data.UserInfoEncryptedResponseAlg != "" && opts.claims.UserInfoEncryptedResponseAlg != opts.data.UserInfoEncryptedResponseAlg {
		logger.WarnContext(ctx, "User info encrypted response algorithm mismatch", "expected", opts.data.UserInfoEncryptedResponseAlg, "got", opts.claims.UserInfoEncryptedResponseAlg)
		return exceptions.NewValidationError("user info encrypted response algorithm mismatch")
	}
	if opts.claims.UserInfoEncryptedResponseEnc != "" && opts.data.UserInfoEncryptedResponseEnc != "" && opts.claims.UserInfoEncryptedResponseEnc != opts.data.UserInfoEncryptedResponseEnc {
		logger.WarnContext(ctx, "User info encrypted response encoding mismatch", "expected", opts.data.UserInfoEncryptedResponseEnc, "got", opts.claims.UserInfoEncryptedResponseEnc)
		return exceptions.NewValidationError("user info encrypted response encoding mismatch")
	}
	if opts.claims.RequestObjectSigningAlg != "" && opts.data.RequestObjectSigningAlg != "" && opts.claims.RequestObjectSigningAlg != opts.data.RequestObjectSigningAlg {
		logger.WarnContext(ctx, "Request object signed response algorithm mismatch", "expected", opts.data.RequestObjectSigningAlg, "got", opts.claims.RequestObjectSigningAlg)
		return exceptions.NewValidationError("request object signed response algorithm mismatch")
	}
	if opts.claims.RequestObjectEncryptionAlg != "" && opts.data.RequestObjectEncryptionAlg != "" && opts.claims.RequestObjectEncryptionAlg != opts.data.RequestObjectEncryptionAlg {
		logger.WarnContext(ctx, "Request object encrypted response algorithm mismatch", "expected", opts.data.RequestObjectEncryptionAlg, "got", opts.claims.RequestObjectEncryptionAlg)
		return exceptions.NewValidationError("request object encrypted response algorithm mismatch")
	}
	if opts.claims.RequestObjectEncryptionEnc != "" && opts.data.RequestObjectEncryptionEnc != "" && opts.claims.RequestObjectEncryptionEnc != opts.data.RequestObjectEncryptionEnc {
		logger.WarnContext(ctx, "Request object encrypted response encoding mismatch", "expected", opts.data.RequestObjectEncryptionEnc, "got", opts.claims.RequestObjectEncryptionEnc)
		return exceptions.NewValidationError("request object encrypted response encoding mismatch")
	}
	if opts.claims.TokenEndpointAuthSigningAlg != "" && opts.data.TokenEndpointAuthSigningAlg != "" && opts.claims.TokenEndpointAuthSigningAlg != opts.data.TokenEndpointAuthSigningAlg {
		logger.WarnContext(ctx, "Token endpoint auth signing algorithm mismatch", "expected", opts.data.TokenEndpointAuthSigningAlg, "got", opts.claims.TokenEndpointAuthSigningAlg)
		return exceptions.NewValidationError("token endpoint auth signing algorithm mismatch")
	}
	if opts.claims.AccessTokenSigningAlg != "" && opts.data.AccessTokenSigningAlg != "" && opts.claims.AccessTokenSigningAlg != opts.data.AccessTokenSigningAlg {
		logger.WarnContext(ctx, "Access token signing algorithm mismatch", "expected", opts.data.AccessTokenSigningAlg, "got", opts.claims.AccessTokenSigningAlg)
		return exceptions.NewValidationError("access token signing algorithm mismatch")
	}

	logger.InfoContext(ctx, "Validated software statement claims")
	return nil
}
