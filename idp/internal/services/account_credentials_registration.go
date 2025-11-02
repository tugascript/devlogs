// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsRegistrationLocation = "account_credentials_registration"
)

var allowedAccountCredentialsScopes []string = []string{
	string(database.AccountCredentialsScopeEmail),
	string(database.AccountCredentialsScopeProfile),
	string(database.AccountCredentialsScopeAccountAdmin),
	string(database.AccountCredentialsScopeAccountUsersRead),
	string(database.AccountCredentialsScopeAccountUsersWrite),
	string(database.AccountCredentialsScopeAccountAppsRead),
	string(database.AccountCredentialsScopeAccountAppsWrite),
	string(database.AccountCredentialsScopeAccountAppsConfigsRead),
	string(database.AccountCredentialsScopeAccountAppsConfigsWrite),
	string(database.AccountCredentialsScopeAccountCredentialsRead),
	string(database.AccountCredentialsScopeAccountCredentialsWrite),
	string(database.AccountCredentialsScopeAccountCredentialsConfigsRead),
	string(database.AccountCredentialsScopeAccountCredentialsConfigsWrite),
	string(database.AccountCredentialsScopeAccountAuthProvidersRead),
}

type checkAccountCRDomainOptions struct {
	requestID              string
	accountPublicID        uuid.UUID
	domain                 string
	requireVerifiedDomains bool
}

func (s *Services) checkAccountCRDomain(
	ctx context.Context,
	opts checkAccountCRDomainOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, dynamicRegistrationDomainsLocation, "checkAccountCRDomain").With(
		"domain", opts.domain,
	)
	logger.InfoContext(ctx, "Checking account credential domain validity")

	baseDomain, err := publicsuffix.EffectiveTLDPlusOne(opts.domain)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse base domain", "error", err)
		return "", exceptions.NewValidationError("invalid client URI")
	}

	var count int64
	if baseDomain != opts.domain {
		if opts.requireVerifiedDomains {
			count, err = s.database.CountVerifiedDynamicRegistrationDomainsByDomainsAndAccountPublicID(
				ctx,
				database.CountVerifiedDynamicRegistrationDomainsByDomainsAndAccountPublicIDParams{
					AccountPublicID: opts.accountPublicID,
					Domains:         []string{opts.domain, baseDomain},
				},
			)
		} else {
			count, err = s.database.CountDynamicRegistrationDomainsByDomainsAndAccountPublicID(
				ctx,
				database.CountDynamicRegistrationDomainsByDomainsAndAccountPublicIDParams{
					AccountPublicID: opts.accountPublicID,
					Domains:         []string{opts.domain, baseDomain},
				},
			)
		}
	} else {
		if opts.requireVerifiedDomains {
			count, err = s.database.CountVerifiedDynamicRegistrationDomainsByDomainAndAccountPublicID(
				ctx,
				database.CountVerifiedDynamicRegistrationDomainsByDomainAndAccountPublicIDParams{
					AccountPublicID: opts.accountPublicID,
					Domain:          opts.domain,
				},
			)
		} else {
			count, err = s.database.CountDynamicRegistrationDomainsByDomainAndAccountPublicID(
				ctx,
				database.CountDynamicRegistrationDomainsByDomainAndAccountPublicIDParams{
					AccountPublicID: opts.accountPublicID,
					Domain:          opts.domain,
				},
			)
		}
	}

	if err != nil {
		logger.ErrorContext(ctx, "Failed to count verified account dynamic registration domains", "error", err)
		return "", exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.InfoContext(ctx, "Account credential domain is whitelisted")
		return baseDomain, nil
	}

	logger.InfoContext(ctx, "Account credential domain is not whitelisted or verified")
	return "", exceptions.NewUnauthorizedError()
}

type buildAccountCRSoftwareStatementFuncOptions struct {
	requestID           string
	accountPublicID     uuid.UUID
	verificationMethods []database.SoftwareStatementVerificationMethod
	jwksURI             string
	jwks                []string
	domain              string
	baseDomain          string
}

func (s *Services) buildAccountCRSoftwareStatementFunc(
	ctx context.Context,
	opts buildAccountCRSoftwareStatementFuncOptions,
) tokens.GetUnknownPublicJWK {
	logger := s.buildLogger(opts.requestID, accountCredentialsRegistrationLocation, "buildAccountCRSoftwareStatementFunc").With(
		"accountPublicID", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Checking account credential software statement validity")

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
		if len(opts.jwks) > 0 {
			return func(kid string) (utils.JWK, error) {
				jwks := make([]utils.JWK, 0, len(opts.jwks))
				for _, rawJWK := range opts.jwks {
					jwk, err := utils.JsonToJWK([]byte(rawJWK))
					if err != nil {
						logger.ErrorContext(ctx, "Failed to parse manual JWK", "error", err)
						return nil, errors.New("failed to parse manual JWK")
					}
					jwks = append(jwks, jwk)
				}

				jwkIdx := slices.IndexFunc(jwks, func(jwk utils.JWK) bool {
					return jwk.GetKeyID() == kid
				})
				if jwkIdx == -1 {
					logger.WarnContext(ctx, "No matching manual JWK found for KID", "kid", kid)
					return nil, errors.New("no matching manual JWK found for KID")
				}

				sliceJWK := jwks[jwkIdx]
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

func mapAccountCredentialsDRTransport(applicationType database.AccountCredentialsType) database.Transport {
	if applicationType == database.AccountCredentialsTypeMcp {
		return database.TransportStreamableHttp
	}

	return database.TransportHttps
}

type mapAccountCredentialsRegistrationDataToDBParamsOptions struct {
	applicationType         database.AccountCredentialsType
	accountPublicID         uuid.UUID
	accountID               int32
	domain                  string
	requestID               string
	tokenEndpointAuthMethod database.AuthMethod
	transport               database.Transport
	scopes                  []database.AccountCredentialsScope
	data                    *ApplicationRegistrationData
	claims                  *tokens.SoftwareStatementClaims
}

func (s *Services) mapAccountCredentialsRegistrationDataToDBParams(
	ctx context.Context,
	opts mapAccountCredentialsRegistrationDataToDBParamsOptions,
) (database.CreateAccountCredentialsParams, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsRegistrationLocation, "mapAccountCredentialsRegistrationDataToDBParams").With(
		"accountPublicID", opts.accountPublicID,
		"accountID", opts.accountID,
		"domain", opts.domain,
		"data", opts.data,
		"claims", opts.claims,
	)
	logger.InfoContext(ctx, "Mapping account credentials registration data to database params")

	accessTokenSigningAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.data.AccessTokenSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map access token signing alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	responseTypes, serviceErr := mapResponseTypesWithDefault(opts.data.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	grantTypes, serviceErr := mapAccountCredentialsGrantTypes(opts.applicationType, opts.data.GrantTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map grant types", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	subjectType, serviceErr := mapEmptySubjectType(opts.data.SubjectType)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map subject type", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	tokenEndpointAuthSigningAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.TokenEndpointAuthSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map token endpoint auth signing alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	idSignAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.data.IDTokenSignedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token signed response alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	idEncAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.IDTokenEncryptedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token encrypted response alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	idEncEnc, serviceErr := mapEmptyTokenEncryptionEncoding(idEncAlg, opts.data.IDTokenEncryptedResponseEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token encrypted response enc", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	userInfoSignAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.UserInfoSignedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info signed response alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	userInfoEncAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.UserInfoEncryptedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info encrypted response alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	userInfoEncEnc, serviceErr := mapEmptyTokenEncryptionEncoding(userInfoEncAlg, opts.data.UserInfoEncryptedResponseEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info encrypted response enc", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	requestObjectSigningAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.RequestObjectSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object signing alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	requestObjectEncryptionAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.RequestObjectEncryptionAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object encryption alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	requestObjectEncryptionEnc, serviceErr := mapEmptyTokenEncryptionEncoding(requestObjectEncryptionAlg, opts.data.RequestObjectEncryptionEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object encryption enc", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	jwks, serviceErr := mapEmptyJWKs(logger, ctx, opts.data.JWKs)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map JWKs", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	params := database.CreateAccountCredentialsParams{
		AccountID:       opts.accountID,
		AccountPublicID: opts.accountPublicID,
		Domain:          opts.domain,
		CreationMethod:  database.CreationMethodDynamicRegistration,
		Transport:       opts.transport,
		ClientID:        utils.Base62UUID(),
		RedirectUris: utils.MapSlice(opts.data.RedirectURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		TokenEndpointAuthMethod:      opts.tokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:  tokenEndpointAuthSigningAlg,
		AccessTokenSigningAlg:        accessTokenSigningAlg,
		GrantTypes:                   grantTypes,
		ResponseTypes:                responseTypes,
		ClientName:                   opts.data.ClientName,
		ClientUri:                    utils.ProcessURL(opts.data.ClientURI),
		LogoUri:                      mapEmptyURL(opts.data.LogoURI),
		Scopes:                       opts.scopes,
		Contacts:                     opts.data.Contacts,
		TosUri:                       mapEmptyURL(opts.data.TOSURI),
		PolicyUri:                    mapEmptyURL(opts.data.PolicyURI),
		JwksUri:                      mapEmptyURL(opts.data.JWKsURI),
		Jwks:                         jwks,
		SoftwareID:                   mapEmptyString(opts.data.SoftwareID),
		SoftwareVersion:              mapEmptyString(opts.data.SoftwareVersion),
		CredentialsType:              opts.applicationType,
		SectorIdentifierUri:          mapEmptyURL(opts.data.SectorIdentifierURI),
		SubjectType:                  subjectType,
		IDTokenSignedResponseAlg:     idSignAlg,
		IDTokenEncryptedResponseAlg:  idEncAlg,
		IDTokenEncryptedResponseEnc:  idEncEnc,
		UserinfoSignedResponseAlg:    userInfoSignAlg,
		UserinfoEncryptedResponseAlg: userInfoEncAlg,
		UserinfoEncryptedResponseEnc: userInfoEncEnc,
		RequestObjectSigningAlg:      requestObjectSigningAlg,
		RequestObjectEncryptionAlg:   requestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   requestObjectEncryptionEnc,
		DefaultMaxAge:                mapEmptyBigInt(opts.data.DefaultMaxAge),
		RequireAuthTime:              opts.data.RequireAuthTime,
		DefaultAcrValues:             opts.data.DefaultACRValues,
		InitiateLoginUri:             mapEmptyURL(opts.data.InitiateLoginURI),
		RequestUris: utils.MapSlice(opts.data.RequestURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
	}

	if opts.claims != nil {
		if opts.claims.ClientName != "" {
			params.ClientName = opts.claims.ClientName
		}
		if opts.claims.ClientURI != "" {
			params.ClientUri = utils.ProcessURL(opts.claims.ClientURI)
		}
		if opts.claims.LogoURI != "" {
			params.LogoUri = mapEmptyURL(opts.claims.LogoURI)
		}
		if len(opts.claims.RedirectURIs) > 0 {
			params.RedirectUris = utils.MapSlice(opts.claims.RedirectURIs, func(uri *string) string {
				return utils.ProcessURL(*uri)
			})
		}
		if opts.claims.TOSURI != "" {
			params.TosUri = mapEmptyURL(opts.claims.TOSURI)
		}
		if opts.claims.PolicyURI != "" {
			params.PolicyUri = mapEmptyURL(opts.claims.PolicyURI)
		}
		if opts.claims.JWKsURI != "" {
			params.JwksUri = mapEmptyURL(opts.claims.JWKsURI)
		}
		if len(opts.claims.JWKs) > 0 {
			jwks, serviceErr := mapEmptyJWKs(logger, ctx, opts.claims.JWKs)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to map JWKs", "serviceError", serviceErr)
				return database.CreateAccountCredentialsParams{}, serviceErr
			}

			params.Jwks = jwks
		}
		if opts.claims.SoftwareID != "" {
			params.SoftwareID = mapEmptyString(opts.claims.SoftwareID)
		}
		if opts.claims.SoftwareVersion != "" {
			params.SoftwareVersion = mapEmptyString(opts.claims.SoftwareVersion)
		}
		if opts.claims.SectorIdentifierURI != "" {
			params.SectorIdentifierUri = mapEmptyURL(opts.claims.SectorIdentifierURI)
		}
		if opts.claims.SubjectType != "" {
			subjectType, _ := mapEmptySubjectType(opts.claims.SubjectType)
			params.SubjectType = subjectType
		}
		if len(opts.claims.RequestURIs) > 0 {
			params.RequestUris = utils.MapSlice(opts.claims.RequestURIs, func(uri *string) string {
				return utils.ProcessURL(*uri)
			})
		}
		if opts.claims.IDTokenSignedResponseAlg != "" {
			idSignAlg, _ := mapTokenCryptoSuiteWithDefault(opts.claims.IDTokenSignedResponseAlg)
			params.IDTokenSignedResponseAlg = idSignAlg
		}
		if opts.claims.IDTokenEncryptedResponseAlg != "" {
			idEncAlg, _ := mapEmptyTokenEncryptionAlgorithm(opts.claims.IDTokenEncryptedResponseAlg)
			params.IDTokenEncryptedResponseAlg = idEncAlg
		}
		if opts.claims.IDTokenEncryptedResponseEnc != "" {
			idEncEnc, _ := mapEmptyTokenEncryptionEncoding(params.IDTokenEncryptedResponseAlg, opts.claims.IDTokenEncryptedResponseEnc)
			params.IDTokenEncryptedResponseEnc = idEncEnc
		}
		if opts.claims.UserInfoSignedResponseAlg != "" {
			userInfoSignAlg, _ := mapEmptyTokenCryptoSuite(opts.claims.UserInfoSignedResponseAlg)
			params.UserinfoSignedResponseAlg = userInfoSignAlg
		}
		if opts.claims.UserInfoEncryptedResponseAlg != "" {
			userInfoEncAlg, _ := mapEmptyTokenEncryptionAlgorithm(opts.claims.UserInfoEncryptedResponseAlg)
			params.UserinfoEncryptedResponseAlg = userInfoEncAlg
		}
		if opts.claims.UserInfoEncryptedResponseEnc != "" {
			userInfoEncEnc, _ := mapEmptyTokenEncryptionEncoding(params.UserinfoEncryptedResponseAlg, opts.claims.UserInfoEncryptedResponseEnc)
			params.UserinfoEncryptedResponseEnc = userInfoEncEnc
		}
		if opts.claims.RequestObjectSigningAlg != "" {
			requestObjectSigningAlg, _ := mapEmptyTokenCryptoSuite(opts.claims.RequestObjectSigningAlg)
			params.RequestObjectSigningAlg = requestObjectSigningAlg
		}
		if opts.claims.RequestObjectEncryptionAlg != "" {
			requestObjectEncryptionAlg, _ := mapEmptyTokenEncryptionAlgorithm(opts.claims.RequestObjectEncryptionAlg)
			params.RequestObjectEncryptionAlg = requestObjectEncryptionAlg
		}
		if opts.claims.RequestObjectEncryptionEnc != "" {
			requestObjectEncryptionEnc, _ := mapEmptyTokenEncryptionEncoding(params.RequestObjectEncryptionAlg, opts.claims.RequestObjectEncryptionEnc)
			params.RequestObjectEncryptionEnc = requestObjectEncryptionEnc
		}
		if opts.claims.TokenEndpointAuthSigningAlg != "" {
			tokenEndpointAuthSigningAlg, _ := mapEmptyTokenCryptoSuite(opts.claims.TokenEndpointAuthSigningAlg)
			params.TokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg
		}
		if opts.claims.AccessTokenSigningAlg != "" {
			accessTokenSigningAlg, _ := mapTokenCryptoSuiteWithDefault(opts.claims.AccessTokenSigningAlg)
			params.AccessTokenSigningAlg = accessTokenSigningAlg
		}
		if opts.claims.RequireAuthTime {
			params.RequireAuthTime = opts.claims.RequireAuthTime
		}
		if opts.claims.DefaultMaxAge > 0 {
			params.DefaultMaxAge = mapEmptyBigInt(opts.claims.DefaultMaxAge)
		}
		if opts.claims.DefaultACRValues != nil {
			params.DefaultAcrValues = opts.claims.DefaultACRValues
		}
		if opts.claims.InitiateLoginURI != "" {
			params.InitiateLoginUri = mapEmptyURL(opts.claims.InitiateLoginURI)
		}
		if len(opts.claims.GrantTypes) > 0 {
			params.GrantTypes = utils.MapSlice(opts.claims.GrantTypes, func(grantType *string) database.GrantType {
				return database.GrantType(*grantType)
			})
		}
		if len(opts.claims.ResponseTypes) > 0 {
			params.ResponseTypes = utils.MapSlice(opts.claims.ResponseTypes, func(responseType *string) database.ResponseType {
				return database.ResponseType(*responseType)
			})
		}
		if opts.claims.Scope != "" {
			params.Scopes = utils.MapSlice(strings.Fields(opts.claims.Scope), func(scope *string) database.AccountCredentialsScope {
				return database.AccountCredentialsScope(*scope)
			})
		}
		if len(opts.claims.Contacts) > 0 {
			params.Contacts = opts.claims.Contacts
		}
	}

	return params, nil
}

type CreateAccountCredentialsRegistrationOptions struct {
	RequestID                    string
	AccountPublicID              uuid.UUID
	AccountVersion               int32
	IsAuthenticated              bool
	ApplicationType              string
	RedirectURIs                 []string
	TokenEndpointAuthMethod      string
	GrantTypes                   []string
	ResponseTypes                []string
	ClientName                   string
	ClientURI                    string
	LogoURI                      string
	TOSURI                       string
	PolicyURI                    string
	Contacts                     []string
	SoftwareID                   string
	SoftwareVersion              string
	SoftwareStatement            string
	JWKsURI                      string
	JWKs                         []string
	FrontendDomain               string
	BackendDomain                string
	RequireAuthTime              bool
	DefaultMaxAge                int64
	SubjectType                  string
	IDTokenSignedResponseAlg     string
	IDTokenEncryptedResponseAlg  string
	IDTokenEncryptedResponseEnc  string
	RequestObjectSigningAlg      string
	RequestObjectEncryptionAlg   string
	RequestObjectEncryptionEnc   string
	DefaultACRValues             []string
	Scope                        string
	SectorIdentifierURI          string
	InitiateLoginURI             string
	RequestURIs                  []string
	UserInfoSignedResponseAlg    string
	UserInfoEncryptedResponseAlg string
	UserInfoEncryptedResponseEnc string
	TokenEndpointAuthSigningAlg  string
	AccessTokenSigningAlg        string
}

func (s *Services) CreateAccountCredentialsRegistration(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		accountCredentialsRegistrationLocation,
		"CreateAccountCredentialsRegistration",
	).With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Creating account credentials registration...")

	applicationType, serviceErr := mapAccountCredentialsType(opts.ApplicationType)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map application type", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	scopes, serviceErr := mapAccountCredentialsScopes(strings.Fields(opts.Scope))
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map scopes", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	transport := mapAccountCredentialsDRTransport(applicationType)
	tokenEndpointAuthMethod, serviceErr := mapAccountCredentialsTokenEndpointAuthMethod(
		opts.TokenEndpointAuthMethod,
		applicationType,
		transport,
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map token endpoint auth method", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	if !validateEncryptionAlgorithmPair(opts.IDTokenEncryptedResponseAlg, opts.IDTokenEncryptedResponseEnc) {
		logger.WarnContext(ctx, "id_token encryption algorithm and encoding must both be set or both be unset")
		return dtos.AccountCredentialsDTO{}, exceptions.NewValidationError("id_token encryption algorithm and encoding mismatch")
	}
	if !validateEncryptionAlgorithmPair(opts.UserInfoEncryptedResponseAlg, opts.UserInfoEncryptedResponseEnc) {
		logger.WarnContext(ctx, "userinfo encryption algorithm and encoding must both be set or both be unset")
		return dtos.AccountCredentialsDTO{}, exceptions.NewValidationError("userinfo encryption algorithm and encoding mismatch")
	}
	if !validateEncryptionAlgorithmPair(opts.RequestObjectEncryptionAlg, opts.RequestObjectEncryptionEnc) {
		logger.WarnContext(ctx, "request_object encryption algorithm and encoding must both be set or both be unset")
		return dtos.AccountCredentialsDTO{}, exceptions.NewValidationError("request_object encryption algorithm and encoding mismatch")
	}

	accountDRConfigDTO, serviceErr := s.GetAndCacheAccountDynamicRegistrationConfig(ctx, GetAndCacheAccountDynamicRegistrationConfigOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account dynamic registration config not found")
			return dtos.AccountCredentialsDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get account dynamic registration config", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	if slices.Contains(accountDRConfigDTO.RequireInitialAccessTokenCredentialTypes, applicationType) &&
		!opts.IsAuthenticated {
		logger.WarnContext(ctx, "Account dynamic registration configuration needs to contain initial access token")
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	if slices.Contains(accountDRConfigDTO.RequireSoftwareStatementCredentialTypes, applicationType) &&
		opts.SoftwareStatement == "" {
		logger.WarnContext(ctx, "Account dynamic registration configuration needs to contain software statement")
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	_, serviceErr = s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	parsedClientURI, err := url.Parse(opts.ClientURI)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse client URI", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewValidationError("invalid client URI")
	}

	domain := parsedClientURI.Hostname()
	baseDomain, serviceErr := s.checkAccountCRDomain(ctx, checkAccountCRDomainOptions{
		requestID:              opts.RequestID,
		accountPublicID:        opts.AccountPublicID,
		domain:                 domain,
		requireVerifiedDomains: slices.Contains(accountDRConfigDTO.RequireVerifiedDomainsCredentialsType, applicationType),
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to check domain validity", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	data := ApplicationRegistrationData{
		RedirectURIs:                 opts.RedirectURIs,
		TokenEndpointAuthMethod:      opts.TokenEndpointAuthMethod,
		ResponseTypes:                opts.ResponseTypes,
		GrantTypes:                   opts.GrantTypes,
		ApplicationType:              opts.ApplicationType,
		ClientName:                   opts.ClientName,
		ClientURI:                    opts.ClientURI,
		LogoURI:                      opts.LogoURI,
		Scope:                        opts.Scope,
		Contacts:                     opts.Contacts,
		TOSURI:                       opts.TOSURI,
		PolicyURI:                    opts.PolicyURI,
		JWKsURI:                      opts.JWKsURI,
		JWKs:                         opts.JWKs,
		SoftwareID:                   opts.SoftwareID,
		SoftwareVersion:              opts.SoftwareVersion,
		SubjectType:                  opts.SubjectType,
		SectorIdentifierURI:          opts.SectorIdentifierURI,
		DefaultMaxAge:                opts.DefaultMaxAge,
		RequireAuthTime:              opts.RequireAuthTime,
		DefaultACRValues:             opts.DefaultACRValues,
		InitiateLoginURI:             opts.InitiateLoginURI,
		RequestURIs:                  opts.RequestURIs,
		IDTokenSignedResponseAlg:     opts.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  opts.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  opts.IDTokenEncryptedResponseEnc,
		UserInfoSignedResponseAlg:    opts.UserInfoSignedResponseAlg,
		UserInfoEncryptedResponseAlg: opts.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc: opts.UserInfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      opts.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:   opts.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   opts.RequestObjectEncryptionEnc,
		TokenEndpointAuthSigningAlg:  opts.TokenEndpointAuthSigningAlg,
		AccessTokenSigningAlg:        opts.AccessTokenSigningAlg,
	}
	var ssClaimsReference *tokens.SoftwareStatementClaims
	if opts.SoftwareStatement != "" {
		ssClaims, stdClaims, err := s.jwt.VerifySoftwareStatement(ctx, tokens.VerifySoftwareStatementOptions{
			RequestID:         opts.RequestID,
			SoftwareStatement: opts.SoftwareStatement,
			GetPublicJWK: s.buildAccountCRSoftwareStatementFunc(ctx, buildAccountCRSoftwareStatementFuncOptions{
				requestID:           opts.RequestID,
				accountPublicID:     opts.AccountPublicID,
				verificationMethods: accountDRConfigDTO.SoftwareStatementVerificationMethods,
				jwksURI:             opts.JWKsURI,
				jwks:                opts.JWKs,
				domain:              domain,
				baseDomain:          baseDomain,
			}),
		})
		if err != nil {
			logger.WarnContext(ctx, "Failed to verify software statement", "error", err)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if serviceErr := s.verifySoftwareStatementSTDClaims(ctx, verifySoftwareStatementSTDClaimsOptions{
			requestID:      opts.RequestID,
			backendDomain:  opts.BackendDomain,
			frontendDomain: opts.FrontendDomain,
			domain:         domain,
			baseDomain:     baseDomain,
			claims:         &stdClaims,
		}); serviceErr != nil {
			logger.WarnContext(ctx, "Failed to verify software statement standard claims", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		if serviceErr := s.validateSoftwareStatementClaims(ctx, validateSoftwareStatementClaimsOptions{
			requestID:     opts.RequestID,
			claims:        &ssClaims,
			data:          &data,
			allowedScopes: utils.SliceToHashSet(allowedAccountCredentialsScopes),
		}); serviceErr != nil {
			logger.WarnContext(ctx, "Failed to validate software statement claims", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		ssClaimsReference = &ssClaims
	}

	params, serviceErr := s.mapAccountCredentialsRegistrationDataToDBParams(ctx, mapAccountCredentialsRegistrationDataToDBParamsOptions{
		applicationType:         applicationType,
		accountPublicID:         opts.AccountPublicID,
		accountID:               opts.AccountVersion,
		domain:                  domain,
		requestID:               opts.RequestID,
		tokenEndpointAuthMethod: tokenEndpointAuthMethod,
		transport:               transport,
		scopes:                  scopes,
		data:                    &data,
		claims:                  ssClaimsReference,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account credentials registration data to database params", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	if tokenEndpointAuthMethod == database.AuthMethodNone {
		accountCredentials, err := s.database.CreateAccountCredentials(ctx, params)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create account credentials", "error", err)
			return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created account credentials successfully")
		return dtos.MapAccountCredentialsToDTO(&accountCredentials)
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	accountCredentials, err := s.database.CreateAccountCredentials(ctx, params)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account credentials", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}

	switch tokenEndpointAuthMethod {
	case database.AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       accountID,
			accountPublicID: opts.AccountPublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageAccount,
			cryptoSuite:     utils.SupportedCryptoSuite(params.AccessTokenSigningAlg),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		if err = qrs.CreateAccountCredentialKey(ctx, database.CreateAccountCredentialKeyParams{
			AccountID:            accountID,
			AccountCredentialsID: accountCredentials.ID,
			CredentialsKeyID:     clientKey.ID,
			AccountPublicID:      opts.AccountPublicID,
			JwkKid:               clientKey.PublicKid,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account credential key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		return dtos.MapAccountCredentialsToDTOWithJWK(&accountCredentials, jwk, dbPrms.ExpiresAt)
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   accountID,
			storageMode: mapCCSecretStorageMode(string(tokenEndpointAuthMethod)),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageAccount,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		if err = qrs.CreateAccountCredentialSecret(ctx, database.CreateAccountCredentialSecretParams{
			AccountID:            accountID,
			AccountPublicID:      opts.AccountPublicID,
			AccountCredentialsID: accountCredentials.ID,
			CredentialsSecretID:  ccID,
			SecretID:             secretID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account credential secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		return dtos.MapAccountCredentialsToDTOWithSecret(&accountCredentials, secretID, secret, exp)
	default:
		logger.ErrorContext(ctx, "Invalid token endpoint auth method", "tokenEndpointAuthMethod", tokenEndpointAuthMethod)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.AccountCredentialsDTO{}, serviceErr
	}
}
