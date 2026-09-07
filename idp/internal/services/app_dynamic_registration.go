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
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
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
	claims                  *tokens.SoftwareStatementClaims
}

func (s *Services) mapAppRegistrationDataToDBParams(
	ctx context.Context,
	opts mapAppRegistrationDataToDBParamsOptions,
) (database.CreateAppParams, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appDynamicRegistrationLocation, "mapAppRegistrationDataToDBParams").With(
		"accountPublicID", opts.accountPublicID,
		"accountID", opts.accountID,
		"domain", opts.domain,
		"data", opts.data,
		"claims", opts.claims,
	)
	logger.InfoContext(ctx, "Mapping app registration data to database params")

	responseTypes, serviceErr := mapResponseTypesWithDefault(opts.data.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return database.CreateAppParams{}, serviceErr
	}

	grantTypes, serviceErr := mapAppGrantTypes(opts.appType, opts.data.GrantTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map grant types", "serviceError", serviceErr)
		return database.CreateAppParams{}, serviceErr
	}

	params := database.CreateAppParams{
		AccountID:               opts.accountID,
		AccountPublicID:         opts.accountPublicID,
		AppType:                 opts.appType,
		ClientName:              opts.data.ClientName,
		ClientID:                utils.Base62UUID(),
		ClientUri:               utils.ProcessURL(opts.data.ClientURI),
		UsernameColumn:          opts.usernameColumn,
		TokenEndpointAuthMethod: opts.tokenEndpointAuthMethod,
		CreationMethod:          database.CreationMethodDynamicRegistration,
		GrantTypes:              grantTypes,
		LogoUri:                 mapEmptyURL(opts.data.LogoURI),
		TosUri:                  mapEmptyURL(opts.data.TOSURI),
		PolicyUri:               mapEmptyURL(opts.data.PolicyURI),
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
			return utils.ProcessURL(*uri)
		}),
		ResponseTypes:         responseTypes,
		AllowUserRegistration: opts.allowUserRegistration,
		AuthProviders:         opts.authProviders,
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
		if opts.claims.SoftwareID != "" {
			params.SoftwareID = mapEmptyString(opts.claims.SoftwareID)
		}
		if opts.claims.SoftwareVersion != "" {
			params.SoftwareVersion = mapEmptyString(opts.claims.SoftwareVersion)
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
			scopesList := strings.Fields(opts.claims.Scope)
			stdScopes, customScopes, _, _, serviceErr := mapScopesToStandardAndCustomScopes(scopesList, nil)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to map scopes from software statement", "serviceError", serviceErr)
				return database.CreateAppParams{}, serviceErr
			}
			params.Scopes = stdScopes
			params.CustomScopes = customScopes
		}
		if len(opts.claims.Contacts) > 0 {
			params.Contacts = utils.MapSlice(opts.claims.Contacts, func(t *string) string {
				return utils.Lowered(*t)
			})
		}
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

	appType, serviceErr := mapAppTypeToDB(opts.ApplicationType)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map application type", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	transport := mapAppDRTransport(appType)
	tokenEndpointAuthMethod, serviceErr := mapAppTokenEndpointAuthMethod(
		opts.TokenEndpointAuthMethod,
		appType,
	)
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

	baseDomain, serviceErr := s.checkClientRegistrationDomain(ctx, checkClientRegistrationDomainOptions{
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
			GetPublicJWK: s.buildDynamicRegistrationSoftwareStatementFunc(ctx, buildDynamicRegistrationSoftwareStatementFuncOptions{
				requestID:           opts.RequestID,
				accountPublicID:     accountDTO.PublicID,
				verificationMethods: appDRConfigDTO.SoftwareStatementVerificationMethods,
				jwksURI:             opts.JWKsURI,
				jwks:                opts.JWKs,
				domain:              domain,
				baseDomain:          baseDomain,
			}),
		})
		if err != nil {
			logger.WarnContext(ctx, "Failed to verify software statement", "error", err)
			return dtos.AppDTO{}, exceptions.NewInvalidTokenError("invalid software statement")
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
			return dtos.AppDTO{}, serviceErr
		}

		if serviceErr := s.validateSoftwareStatementClaims(ctx, validateSoftwareStatementClaimsOptions{
			requestID:     opts.RequestID,
			claims:        &ssClaims,
			allowedScopes: utils.SliceToHashSet(allowedAppScopes),
		}); serviceErr != nil {
			logger.WarnContext(ctx, "Failed to validate software statement claims", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		ssClaimsReference = &ssClaims
	}

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
		claims:                  ssClaimsReference,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app registration data to database params", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if tokenEndpointAuthMethod == database.AuthMethodNone {
		app, err := s.database.CreateApp(ctx, params)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created app successfully")
		return dtos.MapAppToDTO(&app), nil
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

	app, err := s.database.CreateApp(ctx, params)
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
			return dtos.MapBackendAppWithJWKToDTO(&app, jwk, dbPrms.ExpiresAt), nil
		}

		return dtos.MapWebAppWithJWKToDTO(&app, jwk, dbPrms.ExpiresAt), nil
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
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
			return dtos.MapBackendAppWithSecretToDTO(&app, secretID, secret, exp), nil
		}

		return dtos.MapWebAppWithSecretToDTO(&app, secretID, secret, exp), nil
	default:
		logger.ErrorContext(ctx, "Invalid token endpoint auth method", "tokenEndpointAuthMethod", tokenEndpointAuthMethod)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.AppDTO{}, serviceErr
	}
}
