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
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appDynamicRegistrationLocation = "app_dynamic_registration"

var allowedAppScopes []string = []string{
	string(database.ScopesOpenid),
	string(database.ScopesEmail),
	string(database.ScopesProfile),
	string(database.ScopesAddress),
	string(database.ScopesPhone),
}

var appDynamicRegistrationUsages []database.DynamicRegistrationUsage = []database.DynamicRegistrationUsage{
	database.DynamicRegistrationUsageApp,
}

func mapAppDRTransport(appType database.AppType) database.Transport {
	if appType == database.AppTypeMcp {
		return database.TransportStreamableHttp
	}

	return database.TransportHttps
}

func mapAppGrantTypes(
	appType database.AppType,
	grantTypes []string,
) ([]database.GrantType, *exceptions.ServiceError) {
	if len(grantTypes) == 0 {
		switch appType {
		case database.AppTypeWeb, database.AppTypeSpa, database.AppTypeNative, database.AppTypeMcp:
			return authCodeAppGrantTypes, nil
		case database.AppTypeBackend, database.AppTypeService:
			return []database.GrantType{
				database.GrantTypeClientCredentials,
				database.GrantTypeUrnIetfParamsOauthGrantTypeJwtBearer,
			}, nil
		case database.AppTypeDevice:
			return deviceGrantTypes, nil
		default:
			return nil, exceptions.NewValidationError("invalid app type")
		}
	}

	gts := make([]database.GrantType, 0, len(grantTypes))
	for _, grantType := range grantTypes {
		mappedGrantType, serviceErr := mapGrantType(grantType)
		if serviceErr != nil {
			return nil, serviceErr
		}
		gts = append(gts, mappedGrantType)
	}

	return gts, nil
}

func mapAppTokenEndpointAuthMethod(
	authMethod string,
	appType database.AppType,
) (database.AuthMethod, *exceptions.ServiceError) {
	if authMethod == "" {
		switch appType {
		case database.AppTypeWeb, database.AppTypeSpa, database.AppTypeNative:
			return database.AuthMethodClientSecretPost, nil
		case database.AppTypeBackend, database.AppTypeService:
			return database.AuthMethodPrivateKeyJwt, nil
		case database.AppTypeDevice, database.AppTypeMcp:
			return database.AuthMethodNone, nil
		default:
			return "", exceptions.NewValidationError("invalid app type")
		}
	}

	mappedAuthMethod, serviceErr := mapAuthMethod(authMethod)
	if serviceErr != nil {
		return "", serviceErr
	}

	switch appType {
	case database.AppTypeWeb, database.AppTypeSpa, database.AppTypeNative:
		if mappedAuthMethod == database.AuthMethodNone {
			return "", exceptions.NewValidationError("auth method none is not supported for web, spa, or native apps")
		}
	case database.AppTypeBackend, database.AppTypeService:
		if mappedAuthMethod == database.AuthMethodNone {
			return "", exceptions.NewValidationError("auth method none is not supported for backend or service apps")
		}
	case database.AppTypeDevice, database.AppTypeMcp:
		if mappedAuthMethod != database.AuthMethodNone {
			return "", exceptions.NewValidationError("only auth method none is supported for device or mcp apps")
		}
	}

	return mappedAuthMethod, nil
}

type mapAppRegistrationDataToDBParamsOptions struct {
	appType                 database.AppType
	accountPublicID         uuid.UUID
	accountID               int32
	domain                  string
	requestID               string
	tokenEndpointAuthMethod database.AuthMethod
	transport               database.Transport
	scopes                  []database.Scopes
	customScopes            []string
	defaultScopes           []database.Scopes
	defaultCustomScopes     []string
	allowUserRegistration   bool
	usernameColumn          database.AppUsernameColumn
	authProviders           []database.AuthProvider
	data                    *ApplicationRegistrationData
}

func (s *Services) mapAppRegistrationDataToDBParams(
	ctx context.Context,
	opts mapAppRegistrationDataToDBParamsOptions,
) (database.CreateRegisteredAppParams, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appDynamicRegistrationLocation, "mapAppRegistrationDataToDBParams").With(
		"accountPublicID", opts.accountPublicID,
		"accountID", opts.accountID,
		"domain", opts.domain,
		"data", opts.data,
	)
	logger.InfoContext(ctx, "Mapping app registration data to database params")

	responseTypes, serviceErr := mapRegistrationResponseTypes(opts.data.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	grantTypes, serviceErr := mapAppGrantTypes(opts.appType, opts.data.GrantTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map grant types", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	subjectType, serviceErr := mapEmptySubjectType(opts.data.SubjectType)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map subject type", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	tokenEndpointAuthSigningAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.TokenEndpointAuthSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map token endpoint auth signing alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	idSignAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.data.IDTokenSignedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token signed response alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	idEncAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.IDTokenEncryptedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token encrypted response alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	idEncEnc, serviceErr := mapEmptyTokenEncryptionEncoding(idEncAlg, opts.data.IDTokenEncryptedResponseEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map ID token encrypted response enc", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	userInfoSignAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.UserInfoSignedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info signed response alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	userInfoEncAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.UserInfoEncryptedResponseAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info encrypted response alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	userInfoEncEnc, serviceErr := mapEmptyTokenEncryptionEncoding(userInfoEncAlg, opts.data.UserInfoEncryptedResponseEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user info encrypted response enc", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	requestObjectSigningAlg, serviceErr := mapEmptyTokenCryptoSuite(opts.data.RequestObjectSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object signing alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	requestObjectEncryptionAlg, serviceErr := mapEmptyTokenEncryptionAlgorithm(opts.data.RequestObjectEncryptionAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object encryption alg", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	requestObjectEncryptionEnc, serviceErr := mapEmptyTokenEncryptionEncoding(requestObjectEncryptionAlg, opts.data.RequestObjectEncryptionEnc)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map request object encryption enc", "serviceError", serviceErr)
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	var jsonJwks []byte
	if opts.data.JWKs != nil && len(opts.data.JWKs.Keys) > 0 {
		var err error
		jsonJwks, err = opts.data.JWKs.MarshalJSON()
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal JWKs to JSON", "error", err)
			return database.CreateRegisteredAppParams{}, exceptions.NewInternalServerError()
		}
	}

	accessTokenSigningAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.data.AccessTokenSigningAlg)
	if serviceErr != nil {
		return database.CreateRegisteredAppParams{}, serviceErr
	}

	params := database.CreateRegisteredAppParams{
		JwksUri:                      mapEmptyURL(opts.data.JWKsURI),
		Jwks:                         jsonJwks,
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
		TokenEndpointAuthSigningAlg:  tokenEndpointAuthSigningAlg,
		DefaultMaxAge:                pgtype.Int4{Int32: int32(opts.data.DefaultMaxAge), Valid: opts.data.DefaultMaxAge != 0},
		RequireAuthTime:              opts.data.RequireAuthTime,
		DefaultAcrValues:             opts.data.DefaultACRValues,
		InitiateLoginUri:             mapEmptyURL(opts.data.InitiateLoginURI),
		RequestUris:                  opts.data.RequestURIs,
		AccessTokenSigningAlg:        accessTokenSigningAlg,
		AccountID:                    opts.accountID,
		AccountPublicID:              opts.accountPublicID,
		AppType:                      opts.appType,
		ClientName:                   opts.data.ClientName,
		ClientID:                     utils.Base62UUID(),
		ClientUri:                    utils.ProcessURL(opts.data.ClientURI),
		UsernameColumn:               opts.usernameColumn,
		TokenEndpointAuthMethod:      opts.tokenEndpointAuthMethod,
		CreationMethod:               database.CreationMethodDynamicRegistration,
		GrantTypes:                   grantTypes,
		LogoUri:                      mapEmptyURL(opts.data.LogoURI),
		TosUri:                       mapEmptyURL(opts.data.TOSURI),
		PolicyUri:                    mapEmptyURL(opts.data.PolicyURI),
		Contacts: utils.MapSlice(opts.data.Contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		SoftwareID:          mapEmptyString(opts.data.SoftwareID),
		SoftwareVersion:     mapEmptyString(opts.data.SoftwareVersion),
		Scopes:              opts.scopes,
		DefaultScopes:       opts.defaultScopes,
		CustomScopes:        opts.customScopes,
		DefaultCustomScopes: opts.defaultCustomScopes,
		Domain:              opts.domain,
		Transport:           opts.transport,
		RedirectUris: utils.MapSlice(opts.data.RedirectURIs, func(uri *string) string {
			return *uri
		}),
		ResponseTypes:         responseTypes,
		AllowUserRegistration: opts.allowUserRegistration,
		AuthProviders:         opts.authProviders,
	}

	return params, nil
}

type CreateAppCredentialsRegistrationOptions struct {
	RequestID                    string
	AccountID                    int32
	IsAuthenticated              bool
	IATDomain                    string
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

func (s *Services) CreateAppCredentialsRegistration(
	ctx context.Context,
	opts CreateAppCredentialsRegistrationOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		appDynamicRegistrationLocation,
		"CreateAppCredentialsRegistration",
	).With(
		"accountID", opts.AccountID,
	)
	logger.InfoContext(ctx, "Creating app credentials registration...")

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
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountID: opts.AccountID, accountPublicID: uuid.Nil,
		data: data, softwareStatement: opts.SoftwareStatement, iatDomain: opts.IATDomain,
		backendDomain: opts.BackendDomain, frontendDomain: opts.FrontendDomain, app: true,
	})
	if preparationErr != nil {
		return dtos.AppDTO{}, preparationErr
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

	appType, serviceErr := mapAppTypeToDB(opts.ApplicationType)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map application type", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	transport := mapAppDRTransport(appType)
	tokenEndpointAuthMethod, serviceErr := mapAuthMethod(opts.TokenEndpointAuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map token endpoint auth method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accessTokenSigningAlg, serviceErr := mapTokenCryptoSuiteWithDefault(opts.AccessTokenSigningAlg)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map access token signing alg", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if !validateEncryptionAlgorithmPair(opts.IDTokenEncryptedResponseAlg, opts.IDTokenEncryptedResponseEnc) {
		logger.WarnContext(ctx, "id_token encryption algorithm and encoding must both be set or both be unset")
		return dtos.AppDTO{}, exceptions.NewValidationError("id_token encryption algorithm and encoding mismatch")
	}
	if !validateEncryptionAlgorithmPair(opts.UserInfoEncryptedResponseAlg, opts.UserInfoEncryptedResponseEnc) {
		logger.WarnContext(ctx, "userinfo encryption algorithm and encoding must both be set or both be unset")
		return dtos.AppDTO{}, exceptions.NewValidationError("userinfo encryption algorithm and encoding mismatch")
	}
	if !validateEncryptionAlgorithmPair(opts.RequestObjectEncryptionAlg, opts.RequestObjectEncryptionEnc) {
		logger.WarnContext(ctx, "request_object encryption algorithm and encoding must both be set or both be unset")
		return dtos.AppDTO{}, exceptions.NewValidationError("request_object encryption algorithm and encoding mismatch")
	}

	parsedClientURI, err := url.Parse(opts.ClientURI)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse client URI", "error", err)
		return dtos.AppDTO{}, exceptions.NewValidationError("invalid client URI")
	}
	domain := parsedClientURI.Hostname()

	appDRConfigDTO, serviceErr := s.GetAndCacheAppDynamicRegistrationConfig(ctx, GetAndCacheAppDynamicRegistrationConfigOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App dynamic registration config not found")
			return dtos.AppDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get app dynamic registration config", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if slices.Contains(appDRConfigDTO.RequireInitialAccessTokenAppTypes, appType) &&
		!opts.IsAuthenticated {
		logger.WarnContext(ctx, "App dynamic registration configuration requires initial access token")
		return dtos.AppDTO{}, exceptions.NewUnauthorizedError()
	}

	if !slices.Contains(appDRConfigDTO.AllowedAppTypes, appType) {
		logger.WarnContext(ctx, "App type is not allowed", "appType", appType)
		return dtos.AppDTO{}, exceptions.NewForbiddenError()
	}

	if slices.Contains(appDRConfigDTO.RequireSoftwareStatementAppTypes, appType) &&
		opts.SoftwareStatement == "" {
		logger.WarnContext(ctx, "App dynamic registration configuration requires software statement")
		return dtos.AppDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account by ID", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if opts.AccountVersion != 0 && accountDTO.Version() != opts.AccountVersion {
		logger.WarnContext(ctx, "Account version mismatch",
			"providedVersion", opts.AccountVersion,
			"currentVersion", accountDTO.Version(),
		)
		return dtos.AppDTO{}, exceptions.NewUnauthorizedError()
	}

	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID:  opts.RequestID,
		accountID:  opts.AccountID,
		name:       opts.ClientName,
		softwareID: opts.SoftwareID,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	_, serviceErr = s.checkClientRegistrationDomain(ctx, checkClientRegistrationDomainOptions{
		requestID:              opts.RequestID,
		accountPublicID:        accountDTO.PublicID,
		iatDomain:              opts.IATDomain,
		usages:                 appDynamicRegistrationUsages,
		domain:                 domain,
		requireVerifiedDomains: slices.Contains(appDRConfigDTO.RequireVerifiedDomainsAppTypes, appType),
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to check domain validity", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	scopesList := strings.Fields(opts.Scope)
	defaultScopesList := utils.MapSlice(appDRConfigDTO.DefaultScopes, func(s *database.Scopes) string {
		return string(*s)
	})
	stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, serviceErr := mapScopesToStandardAndCustomScopes(
		scopesList,
		defaultScopesList,
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map scopes", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	allowedScopesSet := utils.SliceToHashSet(utils.MapSlice(appDRConfigDTO.DefaultAllowedScopes, func(s *database.Scopes) string {
		return string(*s)
	}))
	for _, scope := range stdScopes {
		if !allowedScopesSet.Contains(string(scope)) {
			logger.WarnContext(ctx, "Scope is not allowed", "scope", scope)
			return dtos.AppDTO{}, exceptions.NewValidationError("scope is not allowed: " + string(scope))
		}
	}

	allowUserRegistration := appDRConfigDTO.DefaultAllowUserRegistration
	usernameColumn := appDRConfigDTO.DefaultUsernameColumn
	authProviders := appDRConfigDTO.DefaultAuthProviders

	params, serviceErr := s.mapAppRegistrationDataToDBParams(ctx, mapAppRegistrationDataToDBParamsOptions{
		appType:                 appType,
		accountPublicID:         accountDTO.PublicID,
		accountID:               opts.AccountID,
		domain:                  domain,
		requestID:               opts.RequestID,
		tokenEndpointAuthMethod: tokenEndpointAuthMethod,
		transport:               transport,
		scopes:                  stdScopes,
		customScopes:            customScopes,
		defaultScopes:           defaultStdScopes,
		defaultCustomScopes:     defaultCustomScopes,
		allowUserRegistration:   allowUserRegistration,
		usernameColumn:          usernameColumn,
		authProviders:           authProviders,
		data:                    &data,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app registration data to database params", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if tokenEndpointAuthMethod == database.AuthMethodNone || (tokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt && (data.JWKs != nil || data.JWKsURI != "")) {
		app, err := s.database.CreateRegisteredApp(ctx, params)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created app successfully")
		return s.finalizeRegisteredApp(ctx, opts, accountDTO, &app, "", time.Time{}, nil)
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := qrs.CreateRegisteredApp(ctx, params)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	switch tokenEndpointAuthMethod {
	case database.AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       opts.AccountID,
			accountPublicID: accountDTO.PublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageApp,
			cryptoSuite:     utils.SupportedCryptoSuite(accessTokenSigningAlg),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AccountID:        opts.AccountID,
			AppID:            app.ID,
			CredentialsKeyID: clientKey.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if appType == database.AppTypeBackend || appType == database.AppTypeService {
			return s.finalizeRegisteredApp(ctx, opts, accountDTO, &app, "", dbPrms.ExpiresAt, jwk)
		}

		return s.finalizeRegisteredApp(ctx, opts, accountDTO, &app, "", dbPrms.ExpiresAt, jwk)
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		var ccID int32
		var secret string
		var exp time.Time
		ccID, _, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   opts.AccountID,
			storageMode: mapCCSecretStorageMode(string(tokenEndpointAuthMethod)),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageApp,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: opts.AccountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: ccID,
			AccountID:           opts.AccountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if appType == database.AppTypeBackend || appType == database.AppTypeService {
			return s.finalizeRegisteredApp(ctx, opts, accountDTO, &app, secret, exp, nil)
		}

		return s.finalizeRegisteredApp(ctx, opts, accountDTO, &app, secret, exp, nil)
	default:
		logger.ErrorContext(ctx, "Invalid token endpoint auth method", "tokenEndpointAuthMethod", tokenEndpointAuthMethod)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.AppDTO{}, serviceErr
	}
}

func (s *Services) finalizeRegisteredApp(
	ctx context.Context,
	opts CreateAppCredentialsRegistrationOptions,
	accountDTO dtos.AccountDTO,
	app *database.App,
	secret string,
	expiry time.Time,
	key utils.JWK,
) (dtos.AppDTO, *exceptions.ServiceError) {
	dto := dtos.MapRegisteredApp(app, opts.SoftwareStatement, secret, expiry, key)
	token, serviceErr := s.CreateAppCredentialsRegistrationAccessToken(ctx, CreateAppCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		AccountVersion:  accountDTO.Version(),
		ClientID:        app.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}
	issuer := accountDTO.Username + "." + opts.BackendDomain
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(issuer, app.ClientID))
	return dto, nil
}
