// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const softwareStatementLocation = "software_statement"

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
	JWKs                         *utils.JWKSet
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
	logger := s.buildLogger(opts.requestID, softwareStatementLocation, "verifySoftwareStatementSTDClaims").With(
		"domain", opts.domain,
		"baseDomain", opts.baseDomain,
	)
	logger.InfoContext(ctx, "Verifying software statement standard claims")

	if opts.claims.Issuer != fmt.Sprintf("https://%s", opts.baseDomain) &&
		opts.claims.Issuer != fmt.Sprintf("https://%s", opts.domain) {
		logger.WarnContext(ctx, "Software statement issuer does not match client URI domain or base domain",
			"issuer", opts.claims.Issuer,
		)
		return exceptions.NewUnauthorizedTokenError("issuer does not match client URI domain or base domain")
	}
	if opts.claims.Audience == nil || !slices.ContainsFunc(opts.claims.Audience, func(aud string) bool {
		return aud == fmt.Sprintf("https://%s", opts.frontendDomain) || aud == fmt.Sprintf("https://%s", opts.backendDomain)
	}) {
		logger.WarnContext(ctx, "Software statement audience does not match frontend or backend domain",
			"audience", opts.claims.Audience,
		)
		return exceptions.NewUnauthorizedTokenError("audience does not match frontend or backend")
	}
	if opts.claims.IssuedAt == nil || opts.claims.IssuedAt.Time.IsZero() || opts.claims.IssuedAt.Time.After(time.Now()) {
		logger.WarnContext(ctx, "Software statement issued at claim is invalid",
			"issuedAt", opts.claims.IssuedAt,
		)
		return exceptions.NewUnauthorizedTokenError("issued at claim is invalid")
	}
	if opts.claims.NotBefore != nil && !opts.claims.NotBefore.Time.IsZero() && opts.claims.NotBefore.Time.After(time.Now()) {
		logger.WarnContext(ctx, "Software statement not before claim is invalid",
			"notBefore", opts.claims.NotBefore,
		)
		return exceptions.NewUnauthorizedTokenError("not before claim is invalid")
	}
	if opts.claims.ExpiresAt == nil || opts.claims.ExpiresAt.Time.IsZero() || opts.claims.ExpiresAt.Time.Before(time.Now()) {
		logger.WarnContext(ctx, "Software statement expiration claim is invalid",
			"expiresAt", opts.claims.ExpiresAt,
		)
		return exceptions.NewUnauthorizedTokenError("expiresAt claim is invalid")
	}

	logger.InfoContext(ctx, "Verified software statement standard claims")
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
	allowedScopes utils.HashSet[string]
}

func (s *Services) validateSoftwareStatementClaims(
	ctx context.Context,
	opts validateSoftwareStatementClaimsOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(
		opts.requestID,
		softwareStatementLocation,
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
	}

	if opts.claims.JWKs != nil && opts.claims.JWKsURI != "" {
		logger.WarnContext(ctx, "Both jwks and jwks_uri are set in software statement")
		return exceptions.NewValidationError("both jwks and jwks_uri are set")
	}

	if opts.claims.JWKs != nil && len(opts.claims.JWKs.Keys) > 0 {
		if err := opts.claims.JWKs.Validate(); err != nil {
			logger.WarnContext(ctx, "JWKs jet is invalid", "error", err)
			return exceptions.NewValidationError("jwks is invalid")
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

	logger.InfoContext(ctx, "Validated software statement claims")
	return nil
}

type buildDynamicRegistrationSoftwareStatementFuncOptions struct {
	requestID           string
	accountPublicID     uuid.UUID
	verificationMethods []database.SoftwareStatementVerificationMethod
	jwksURI             string
	jwks                *utils.JWKSet
	domain              string
	baseDomain          string
}

func (s *Services) buildDynamicRegistrationSoftwareStatementFunc(
	ctx context.Context,
	opts buildDynamicRegistrationSoftwareStatementFuncOptions,
) tokens.GetUnknownPublicJWK {
	logger := s.buildLogger(opts.requestID, softwareStatementLocation, "buildDynamicRegistrationSoftwareStatementFunc").With(
		"accountPublicID", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Checking dynamic registration software statement validity")

	if slices.Contains(opts.verificationMethods, database.SoftwareStatementVerificationMethodJwksUri) && opts.jwksURI != "" {
		return func(kid string) (utils.JWK, error) {
			parsedURI, err := url.Parse(opts.jwksURI)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to parse JWKs URI", "error", err)
				return nil, errors.New("invalid JWKs URI")
			}
			if parsedURI.Host != opts.baseDomain || !strings.Contains(parsedURI.Host, "."+opts.baseDomain) {
				logger.WarnContext(ctx, "JWKs URI parsedURI does not match client URI parsedURI")
				return nil, errors.New("JWKs URI parsedURI does not match client URI parsedURI")
			}

			jwks, err := s.jwt.GetPublicJWKs(ctx, tokens.GetPublicJWKsOptions{
				RequestID: opts.requestID,
				URL:       opts.jwksURI,
			})
			if err != nil {
				logger.WarnContext(ctx, "Failed to get public JWKs from JWKs URI", "error", err)
				return nil, errors.New("failed to get public JWKs from JWKs URI")
			}

			jwkIdx := slices.IndexFunc(jwks.Keys, func(jwk utils.JWK) bool {
				return jwk.GetKeyID() == kid
			})
			if jwkIdx == -1 {
				logger.WarnContext(ctx, "No matching JWK found for KID in JWKs URI", "kid", kid)
				return nil, errors.New("no matching JWK found for KID in JWKs URI")
			}

			return jwks.Keys[jwkIdx], nil
		}
	}
	if slices.Contains(opts.verificationMethods, database.SoftwareStatementVerificationMethodManual) {
		if opts.jwks != nil && len(opts.jwks.Keys) > 0 {
			return func(kid string) (utils.JWK, error) {
				jwkIdx := slices.IndexFunc(opts.jwks.Keys, func(jwk utils.JWK) bool {
					return jwk.GetKeyID() == kid
				})
				if jwkIdx == -1 {
					logger.WarnContext(ctx, "No matching manual JWK found for KID", "kid", kid)
					return nil, errors.New("no matching manual JWK found for KID")
				}

				sliceJWK := opts.jwks.Keys[jwkIdx]
				jwkRefEnt, err := s.database.FindDynamicRegistrationSoftwareStatementKeysByCredentialsKeyKIDAndAccountPublicID(
					ctx,
					database.FindDynamicRegistrationSoftwareStatementKeysByCredentialsKeyKIDAndAccountPublicIDParams{
						CredentialsKeyKid: kid,
						AccountPublicID:   opts.accountPublicID,
					},
				)
				if err != nil {
					serviceErr := exceptions.FromDBError(err)
					if serviceErr.Code == exceptions.CodeNotFound {
						logger.WarnContext(ctx, "No database entry found for manual JWK", "kid", kid, "error", err)
						return nil, errors.New("no database entry found for manual JWK")
					}

					logger.ErrorContext(ctx, "Failed to find database entry for manual JWK", "kid", kid, "error", err)
					return nil, errors.New("failed to find database entry for manual JWK")
				}
				if jwkRefEnt.RootDomain != opts.baseDomain {
					logger.WarnContext(ctx, "Manual JWK root domain does not match client URI base domain",
						"kid", kid, "jwkRootDomain", jwkRefEnt.RootDomain, "baseDomain", opts.baseDomain,
					)
					return nil, errors.New("manual JWK root domain does not match client URI base domain")
				}

				jwkEnt, err := s.database.FindCredentialsKeyByID(ctx, jwkRefEnt.CredentialsKeyID)
				if err != nil {
					serviceErr := exceptions.FromDBError(err)
					if serviceErr.Code == exceptions.CodeNotFound {
						logger.WarnContext(ctx, "No credentials key found for manual JWK", "kid", kid, "error", err)
						return nil, errors.New("no credentials key found for manual JWK")
					}

					logger.ErrorContext(ctx, "Failed to find credentials key for manual JWK", "kid", kid, "error", err)
					return nil, errors.New("failed to find credentials key for manual JWK")
				}

				entJWK, err := utils.JsonToJWK(jwkEnt.PublicKey)
				if err != nil {
					logger.ErrorContext(ctx, "Failed to parse manual JWK", "error", err)
					return nil, errors.New("failed to parse manual JWK")
				}
				if !entJWK.ComparePublicKey(sliceJWK) {
					logger.WarnContext(ctx, "Manual JWK does not match database credentials key", "kid", kid)
					return nil, errors.New("manual JWK does not match database credentials key")
				}

				return sliceJWK, nil
			}
		}

		return func(kid string) (utils.JWK, error) {
			jwkEntity, err := s.database.FindDynamicRegistrationSoftwareStatementKeysByRootDomainAndAccountPublicID(
				ctx,
				database.FindDynamicRegistrationSoftwareStatementKeysByRootDomainAndAccountPublicIDParams{
					RootDomain:      opts.baseDomain,
					AccountPublicID: opts.accountPublicID,
				},
			)
			if err != nil {
				if exceptions.FromDBError(err).Code == exceptions.CodeNotFound {
					logger.WarnContext(ctx, "No manual JWKs found for software statement", "error", err)
					return nil, errors.New("no manual JWKs found for software statement")
				}

				logger.ErrorContext(ctx, "Failed to find manual JWKs for software statement", "error", err)
				return nil, errors.New("failed to find manual JWKs for software statement")
			}
			if jwkEntity.PublicKid != kid {
				logger.WarnContext(ctx, "No matching manual JWK found for KID",
					"kid", kid, "publicKID", jwkEntity.PublicKid,
				)
				return nil, errors.New("no matching manual JWK found for KID")
			}

			jwk, err := utils.JsonToJWK(jwkEntity.PublicKey)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to parse manual JWK for software statement", "error", err)
				return nil, errors.New("failed to parse manual JWK for software statement")
			}

			return jwk, nil
		}
	}

	return func(kid string) (utils.JWK, error) {
		logger.WarnContext(ctx, "No verification method available for software statement")
		return nil, errors.New("no verification method available")
	}
}
