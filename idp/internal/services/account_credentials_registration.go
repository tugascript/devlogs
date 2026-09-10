// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
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

var accountCredentialsRegistrationUsages []database.DynamicRegistrationUsage = []database.DynamicRegistrationUsage{
	database.DynamicRegistrationUsageAccount,
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
	)
	logger.InfoContext(ctx, "Mapping account credentials registration data to database params")

	accessTokenSigningAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.data.AccessTokenSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map access token signing alg", "serviceError", serviceErr)
		return database.CreateAccountCredentialsParams{}, serviceErr
	}

	responseTypes, serviceErr := mapRegistrationResponseTypes(opts.data.ResponseTypes)
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

	var jsonJwks []byte
	if opts.data.JWKs != nil && len(opts.data.JWKs.Keys) > 0 {
		var err error
		jsonJwks, err = opts.data.JWKs.MarshalJSON()
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal JWKs to JSON", "error", err)
			return database.CreateAccountCredentialsParams{}, exceptions.NewInternalServerError()
		}
	}

	params := database.CreateAccountCredentialsParams{
		AccountID:       opts.accountID,
		AccountPublicID: opts.accountPublicID,
		Domain:          opts.domain,
		CreationMethod:  database.CreationMethodDynamicRegistration,
		Transport:       opts.transport,
		ClientID:        utils.Base62UUID(),
		RedirectUris: utils.MapSlice(opts.data.RedirectURIs, func(uri *string) string {
			return *uri
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
		Jwks:                         jsonJwks,
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
			return *uri
		}),
	}

	return params, nil
}

type CreateAccountCredentialsRegistrationOptions struct {
	RequestID                    string
	AccountPublicID              uuid.UUID
	AccountVersion               int32
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
	JWKs                         *utils.JWKSet
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
	iatDomain := registrationDomain(opts.ClientURI, opts.RedirectURIs)
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountID: 0, accountPublicID: opts.AccountPublicID,
		data: data, softwareStatement: opts.SoftwareStatement,
		backendDomain: opts.BackendDomain, frontendDomain: opts.FrontendDomain, app: false,
	})
	if preparationErr != nil {
		return dtos.AccountCredentialsDTO{}, preparationErr
	}
	opts.RedirectURIs = data.RedirectURIs
	opts.TokenEndpointAuthMethod = data.TokenEndpointAuthMethod
	opts.ResponseTypes = data.ResponseTypes
	opts.GrantTypes = data.GrantTypes
	opts.ApplicationType = data.ApplicationType
	opts.ClientName = data.ClientName
	opts.ClientURI = data.ClientURI
	opts.LogoURI = data.LogoURI
	opts.Scope = data.Scope
	opts.Contacts = data.Contacts
	opts.TOSURI = data.TOSURI
	opts.PolicyURI = data.PolicyURI
	opts.JWKsURI = data.JWKsURI
	opts.JWKs = data.JWKs
	opts.SoftwareID = data.SoftwareID
	opts.SoftwareVersion = data.SoftwareVersion
	opts.SubjectType = data.SubjectType
	opts.SectorIdentifierURI = data.SectorIdentifierURI
	opts.DefaultMaxAge = data.DefaultMaxAge
	opts.RequireAuthTime = data.RequireAuthTime
	opts.DefaultACRValues = data.DefaultACRValues
	opts.InitiateLoginURI = data.InitiateLoginURI
	opts.RequestURIs = data.RequestURIs
	opts.IDTokenSignedResponseAlg = data.IDTokenSignedResponseAlg
	opts.IDTokenEncryptedResponseAlg = data.IDTokenEncryptedResponseAlg
	opts.IDTokenEncryptedResponseEnc = data.IDTokenEncryptedResponseEnc
	opts.UserInfoSignedResponseAlg = data.UserInfoSignedResponseAlg
	opts.UserInfoEncryptedResponseAlg = data.UserInfoEncryptedResponseAlg
	opts.UserInfoEncryptedResponseEnc = data.UserInfoEncryptedResponseEnc
	opts.RequestObjectSigningAlg = data.RequestObjectSigningAlg
	opts.RequestObjectEncryptionAlg = data.RequestObjectEncryptionAlg
	opts.RequestObjectEncryptionEnc = data.RequestObjectEncryptionEnc
	opts.TokenEndpointAuthSigningAlg = data.TokenEndpointAuthSigningAlg
	opts.AccessTokenSigningAlg = data.AccessTokenSigningAlg

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
	tokenEndpointAuthMethod, serviceErr := mapAuthMethod(opts.TokenEndpointAuthMethod)
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

	if slices.Contains(accountDRConfigDTO.RequireSoftwareStatementCredentialTypes, applicationType) &&
		opts.SoftwareStatement == "" {
		logger.WarnContext(ctx, "Account dynamic registration configuration needs to contain software statement")
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}
	if opts.AccountVersion != 0 && accountDTO.Version() != opts.AccountVersion {
		logger.WarnContext(ctx, "Account version mismatch",
			"providedVersion", opts.AccountVersion,
			"currentVersion", accountDTO.Version(),
		)
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	accountID := accountDTO.ID()
	parsedClientURI, err := url.Parse(opts.ClientURI)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse client URI", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewValidationError("invalid client URI")
	}

	domain := parsedClientURI.Hostname()
	_, serviceErr = s.checkClientRegistrationDomain(ctx, checkClientRegistrationDomainOptions{
		requestID:              opts.RequestID,
		accountPublicID:        opts.AccountPublicID,
		iatDomain:              iatDomain,
		domain:                 domain,
		usages:                 accountCredentialsRegistrationUsages,
		requireVerifiedDomains: slices.Contains(accountDRConfigDTO.RequireVerifiedDomainsCredentialsType, applicationType),
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to check domain validity", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	params, serviceErr := s.mapAccountCredentialsRegistrationDataToDBParams(ctx, mapAccountCredentialsRegistrationDataToDBParamsOptions{
		applicationType:         applicationType,
		accountPublicID:         opts.AccountPublicID,
		accountID:               accountDTO.ID(),
		domain:                  domain,
		requestID:               opts.RequestID,
		tokenEndpointAuthMethod: tokenEndpointAuthMethod,
		transport:               transport,
		scopes:                  scopes,
		data:                    &data,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account credentials registration data to database params", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	if tokenEndpointAuthMethod == database.AuthMethodNone || (tokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt && (data.JWKs != nil || data.JWKsURI != "")) {
		accountCredentials, err := s.database.CreateAccountCredentials(ctx, params)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create account credentials", "error", err)
			return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created account credentials successfully")
		return s.finalizeAccountCredentialsRegistration(ctx, opts, &accountCredentials, "", time.Time{}, nil)
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

	accountCredentials, err := qrs.CreateAccountCredentials(ctx, params)
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

		return s.finalizeAccountCredentialsRegistration(ctx, opts, &accountCredentials, "", dbPrms.ExpiresAt, jwk)
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

		return s.finalizeAccountCredentialsRegistration(ctx, opts, &accountCredentials, secret, exp, nil)
	default:
		logger.ErrorContext(ctx, "Invalid token endpoint auth method", "tokenEndpointAuthMethod", tokenEndpointAuthMethod)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.AccountCredentialsDTO{}, serviceErr
	}
}

func (s *Services) finalizeAccountCredentialsRegistration(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationOptions,
	row *database.AccountCredential,
	secret string,
	expiry time.Time,
	key utils.JWK,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(row, opts.SoftwareStatement, secret, expiry, key)
	if serviceErr != nil {
		return dto, serviceErr
	}
	token, serviceErr := s.CreateAccountCredentialsRegistrationAccessToken(ctx, CreateAccountCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		ClientID:        row.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(opts.BackendDomain, row.ClientID))
	return dto, nil
}
