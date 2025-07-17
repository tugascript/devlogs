// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const (
	oauthLocation string = "oauth"

	bearerJWTMaxValiditySecs int64 = 300
)

var oauthScopes = []oauth.Scope{oauth.ScopeProfile}

type AccountOAuthURLOptions struct {
	RequestID   string
	Provider    string
	RedirectURL string
}

func (s *Services) AccountOAuthURL(ctx context.Context, opts AccountOAuthURLOptions) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "AccountOAuthURL").With(
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Getting OAuth authorization url...")

	authUrlOpts := oauth.AuthorizationURLOptions{
		RequestID:   opts.RequestID,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var oauthUrl, state string
	var serviceErr *exceptions.ServiceError
	switch opts.Provider {
	case AuthProviderApple:
		oauthUrl, state, serviceErr = s.oauthProviders.GetAppleAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderFacebook:
		oauthUrl, state, serviceErr = s.oauthProviders.GetFacebookAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderGitHub:
		oauthUrl, state, serviceErr = s.oauthProviders.GetGithubAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderGoogle:
		oauthUrl, state, serviceErr = s.oauthProviders.GetGoogleAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderMicrosoft:
		oauthUrl, state, serviceErr = s.oauthProviders.GetMicrosoftAuthorizationURL(ctx, authUrlOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'apple', 'facebook', 'github', 'google' and 'microsoft'")
		return "", exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get authorization url or State", "error", serviceErr)
		return "", serviceErr
	}

	if err := s.cache.AddOAuthState(ctx, cache.AddOAuthStateOptions{
		RequestID:       opts.RequestID,
		State:           state,
		Provider:        opts.Provider,
		DurationSeconds: s.jwt.GetOAuthTTL(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache State", "error", err)
		return "", exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Got authorization url successfully")
	return oauthUrl, nil
}

type extOAuthTokenOptions struct {
	requestID   string
	provider    string
	code        string
	state       string
	redirectURL string
}

func (s *Services) extOAuthToken(
	ctx context.Context,
	logger *slog.Logger,
	opts extOAuthTokenOptions,
) (string, *exceptions.ServiceError) {
	ok, err := s.cache.VerifyOAuthState(ctx, cache.VerifyOAuthStateOptions{
		RequestID: opts.requestID,
		State:     opts.state,
		Provider:  opts.provider,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth State", "error", err)
		return "", exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth State is invalid")
		return "", exceptions.NewValidationError("OAuth State is invalid")
	}

	accessTokenOpts := oauth.AccessTokenOptions{
		RequestID:   opts.requestID,
		Code:        opts.code,
		Scopes:      oauthScopes,
		RedirectURL: opts.redirectURL,
	}
	var token string
	var serviceErr *exceptions.ServiceError
	switch opts.provider {
	case AuthProviderFacebook:
		token, serviceErr = s.oauthProviders.GetFacebookAccessToken(ctx, accessTokenOpts)
	case AuthProviderGitHub:
		token, serviceErr = s.oauthProviders.GetGithubAccessToken(ctx, accessTokenOpts)
	case AuthProviderGoogle:
		token, serviceErr = s.oauthProviders.GetGoogleAccessToken(ctx, accessTokenOpts)
	case AuthProviderMicrosoft:
		token, serviceErr = s.oauthProviders.GetMicrosoftAccessToken(ctx, accessTokenOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'facebook', 'github', 'google' and 'microsoft'")
		return "", exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get oauth access token", "error", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Got access token successfully")
	return token, nil
}

type extOAuthUserOptions struct {
	requestID string
	provider  string
	token     string
}

func (s *Services) extOAuthUser(
	ctx context.Context,
	logger *slog.Logger,
	opts extOAuthUserOptions,
) (oauth.UserData, *exceptions.ServiceError) {
	userDataOpts := oauth.UserDataOptions{
		RequestID: opts.requestID,
		Token:     opts.token,
		Scopes:    oauthScopes,
	}
	var userData oauth.UserData
	var serviceErr *exceptions.ServiceError
	switch opts.provider {
	case AuthProviderFacebook:
		userData, serviceErr = s.oauthProviders.GetFacebookUserData(ctx, userDataOpts)
	case AuthProviderGitHub:
		userData, serviceErr = s.oauthProviders.GetGithubUserData(ctx, userDataOpts)
	case AuthProviderGoogle:
		userData, serviceErr = s.oauthProviders.GetGoogleUserData(ctx, userDataOpts)
	case AuthProviderMicrosoft:
		userData, serviceErr = s.oauthProviders.GetMicrosoftUserData(ctx, userDataOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'github' or 'google'")
		return oauth.UserData{}, exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to fetch userData data", "error", serviceErr)
		return oauth.UserData{}, serviceErr
	}

	if !userData.IsVerified {
		logger.WarnContext(ctx, "External OAuth Provider account is not verified")
		return oauth.UserData{}, exceptions.NewUnauthorizedError()
	}

	return userData, nil
}

type saveExtAccount struct {
	requestID string
	provider  string
	userData  *oauth.UserData
}

func (s *Services) saveExtAccount(
	ctx context.Context,
	logger *slog.Logger,
	opts saveExtAccount,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	accountDto, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.requestID,
		Email:     opts.userData.Email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account by email", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		accountDto, serviceErr := s.CreateAccount(ctx, CreateAccountOptions{
			RequestID:  opts.requestID,
			GivenName:  opts.userData.FirstName,
			FamilyName: opts.userData.LastName,
			Email:      opts.userData.Email,
			Provider:   opts.provider,
			Password:   "",
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create account", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		return accountDto, nil
	}

	authProvider, serviceErr := mapAuthProvider(opts.provider)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth provider", "serviceError", serviceErr)
		return dtos.AccountDTO{}, serviceErr
	}

	prvdrOpts := database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDto.Email,
		Provider: authProvider,
	}
	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, prvdrOpts); err != nil {
		serviceErr = exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find auth Provider", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		if err := s.database.CreateAccountAuthProvider(ctx, database.CreateAccountAuthProviderParams{
			Email:           accountDto.Email,
			Provider:        authProvider,
			AccountPublicID: accountDto.PublicID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create auth Provider", "error", err)
			return dtos.AccountDTO{}, exceptions.FromDBError(err)
		}
	}

	return accountDto, nil
}

type generateOAuthQueryParams struct {
	requestID string
	email     string
	token     string
}

func (s *Services) generateOAuthQueryParams(
	ctx context.Context,
	logger *slog.Logger,
	opts generateOAuthQueryParams,
) (string, *exceptions.ServiceError) {
	oauthTtl := s.jwt.GetOAuthTTL()
	code, err := s.cache.GenerateOAuthCode(ctx, cache.GenerateOAuthOptions{
		RequestID:       opts.requestID,
		Email:           opts.email,
		DurationSeconds: oauthTtl,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate oauth Code", "error", err)
		return "", exceptions.NewServerError()
	}

	queryParams := make(url.Values)
	queryParams.Add("code", code)

	fragmentParams := make(url.Values)
	fragmentParams.Add("token_type", "Bearer")
	fragmentParams.Add("access_token", opts.token)
	fragmentParams.Add("expires_in", strconv.FormatInt(oauthTtl, 10))

	return fmt.Sprintf("%s#%s", queryParams.Encode(), fragmentParams.Encode()), nil
}

type ExtLoginAccountOptions struct {
	RequestID   string
	Provider    string
	Code        string
	State       string
	RedirectURL string
}

func (s *Services) ExtLoginAccount(
	ctx context.Context,
	opts ExtLoginAccountOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "ExtLoginAccount").With(
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "External logging in account...")

	token, serviceErr := s.extOAuthToken(ctx, logger, extOAuthTokenOptions{
		requestID:   opts.RequestID,
		provider:    opts.Provider,
		code:        opts.Code,
		state:       opts.State,
		redirectURL: opts.RedirectURL,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	userData, serviceErr := s.extOAuthUser(ctx, logger, extOAuthUserOptions{
		requestID: opts.RequestID,
		provider:  opts.Provider,
		token:     token,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	accountDTO, serviceErr := s.saveExtAccount(ctx, logger, saveExtAccount{
		requestID: opts.RequestID,
		provider:  opts.Provider,
		userData:  &userData,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.CreateOAuthToken(tokens.AccountOAuthTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeOauthAuthorization,
			TTL:       s.jwt.GetOAuthTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, opts.RequestID),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, opts.RequestID),
		StoreFN:         s.BuildUpdateJWKDEKFn(ctx, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign OAuth Token", "serviceError", serviceErr)
		return "", serviceErr
	}

	return s.generateOAuthQueryParams(ctx, logger, generateOAuthQueryParams{
		requestID: opts.RequestID,
		email:     accountDTO.Email,
		token:     signedToken,
	})
}

type AppleLoginAccountOptions struct {
	RequestID string
	FirstName string
	LastName  string
	Email     string
	Code      string
	State     string
}

func (s *Services) AppleLoginAccount(
	ctx context.Context,
	opts AppleLoginAccountOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "AppleLoginAccount").With(
		"firstName", opts.FirstName,
		"lastName", opts.LastName,
	)
	logger.InfoContext(ctx, "Apple account logging in...")

	ok, err := s.cache.VerifyOAuthState(ctx, cache.VerifyOAuthStateOptions{
		RequestID: opts.RequestID,
		State:     opts.State,
		Provider:  AuthProviderApple,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth State", "error", err)
		return "", exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth State is invalid")
		return "", exceptions.NewValidationError("OAuth State is invalid")
	}

	idToken, serviceErr := s.oauthProviders.GetAppleIDToken(ctx, oauth.AccessTokenOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
		Scopes:    oauthScopes,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get apple AccountID token", "error", serviceErr)
		return "", serviceErr
	}

	ok, serviceErr = s.oauthProviders.ValidateAppleIDToken(ctx, oauth.ValidateAppleIDTokenOptions{
		RequestID: opts.RequestID,
		Token:     idToken,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to validate apple AccountID token", "error", serviceErr)
		return "", serviceErr
	}
	if !ok {
		logger.WarnContext(ctx, "Apple account is not verified")
		return "", exceptions.NewUnauthorizedError()
	}

	userData := oauth.NewAppleUserData(opts.Email, opts.FirstName, opts.LastName)
	accountDTO, serviceErr := s.saveExtAccount(ctx, logger, saveExtAccount{
		requestID: opts.RequestID,
		provider:  AuthProviderApple,
		userData:  &userData,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.CreateOAuthToken(tokens.AccountOAuthTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeOauthAuthorization,
			TTL:       s.jwt.GetOAuthTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, opts.RequestID),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, opts.RequestID),
		StoreFN:         s.BuildUpdateJWKDEKFn(ctx, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth Token", "serviceError", serviceErr)
		return "", exceptions.NewServerError()
	}

	return s.generateOAuthQueryParams(ctx, logger, generateOAuthQueryParams{
		requestID: opts.RequestID,
		email:     accountDTO.Email,
		token:     signedToken,
	})
}

type OAuthLoginAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) OAuthLoginAccount(
	ctx context.Context,
	opts OAuthLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "OAuthLoginAccount").With("accountPublicId", opts.PublicID)
	logger.InfoContext(ctx, "OAuth account logging in...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	ok, err := s.cache.VerifyOAuthCode(ctx, cache.VerifyOAuthCodeOptions{
		RequestID: opts.RequestID,
		Email:     accountDTO.Email,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify OAuth Code", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth Code verification failed")
		return dtos.AuthDTO{}, exceptions.NewValidationError("OAuth Code verification failed")
	}

	if accountDTO.TwoFactorType != database.TwoFactorTypeNone {
		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}

		return authDTO, nil
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"OAuth logged in successfully",
	)
}

func (s *Services) GetAccountPublicJWKs(
	ctx context.Context,
	requestID string,
) (string, dtos.JWKsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, oauthLocation, "GetAccountPublicKeys")
	logger.InfoContext(ctx, "Getting account public JWKs...")

	etag, jwks, serviceErr := s.GetAndCacheGlobalDistributedJWK(ctx, requestID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get distributed JWKs", "error", serviceErr)
		return "", dtos.JWKsDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account public JWKs successfully")
	return etag, dtos.NewJWKsDTO(jwks), nil
}

type ProcessAccountCredentialsScopeOptions struct {
	RequestID string
	Scope     string
}

func (s *Services) ProcessAccountCredentialsScope(
	ctx context.Context,
	opts ProcessAccountCredentialsScopeOptions,
) ([]string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "ProcessAccountCredentialsScope").With(
		"scope", opts.Scope,
	)
	logger.InfoContext(ctx, "Processing account credentials scope...")

	if opts.Scope == "" {
		logger.InfoContext(ctx, "Scope is empty, returning empty scopes")
		return make([]string, 0), nil
	}

	scopesSlice := strings.Split(opts.Scope, " ")
	sliceLen := len(scopesSlice)
	scopesMap := utils.MapSliceToHashSet(scopesSlice)
	mapSize := scopesMap.Size()
	if sliceLen > mapSize {
		logger.WarnContext(ctx, "Scopes contain duplicates",
			"scopesCount", sliceLen,
			"uniqueScopesCount", mapSize,
		)
		return nil, exceptions.NewValidationError("Scopes contain duplicates")
	}

	scopes := make([]string, 0, mapSize)
	for _, scope := range scopesMap.Items() {
		encodedScope := database.AccountCredentialsScope(scope)
		switch encodedScope {
		case database.AccountCredentialsScopeAccountAdmin, database.AccountCredentialsScopeAccountUsersRead,
			database.AccountCredentialsScopeAccountUsersWrite, database.AccountCredentialsScopeAccountAppsRead,
			database.AccountCredentialsScopeAccountAppsWrite, database.AccountCredentialsScopeAccountCredentialsRead,
			database.AccountCredentialsScopeAccountCredentialsWrite,
			database.AccountCredentialsScopeAccountAuthProvidersRead:
			scopes = append(scopes, scope)
		default:
			logger.WarnContext(ctx, "Invalid scope", "scope", scope)
			return nil, exceptions.NewValidationError(fmt.Sprintf("Invalid scope: %s", scope))
		}
	}

	if scopesMap.Contains(tokens.AccountScopeAdmin) {
		logger.InfoContext(ctx, "Scopes contains admin account, returning only admin scope")
		return []string{tokens.AccountScopeAdmin}, nil
	}

	logger.InfoContext(ctx, "Successfully processed account credentials scope")
	return scopes, nil
}

func mapDefaultAccountScopes(
	inputScopes []string,
	credentialsScopes []database.AccountCredentialsScope,
) []string {
	if len(inputScopes) == 0 {
		return utils.MapSlice(credentialsScopes, func(s *database.AccountCredentialsScope) string {
			return string(*s)
		})
	}

	return inputScopes
}

type validateAccountJWTClaimsOptions struct {
	requestID     string
	claims        jwt.RegisteredClaims
	backendDomain string
}

func (s *Services) validateAccountJWTGrantToken(
	ctx context.Context,
	opts validateAccountJWTClaimsOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthLocation, "validateAccountJWTGrantToken")
	logger.InfoContext(ctx, "Validating Account JWT Bearer token claims...")

	if opts.claims.Subject == "" || len(opts.claims.Subject) != 22 {
		logger.ErrorContext(ctx, "JWT Bearer token subject is invalid", "subject", opts.claims.Subject)
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	accountClientsDTO, serviceErr := s.GetAccountCredentialsByPublicID(ctx, GetAccountCredentialsByPublicIDOptions{
		RequestID: opts.requestID,
		ClientID:  opts.claims.Subject,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials by public ID", "serviceError", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	if !slices.Contains(accountClientsDTO.AuthMethods, database.AuthMethodPrivateKeyJwt) {
		logger.InfoContext(ctx, "Account credentials does not support JWT Bearer login",
			"clientID", opts.claims.Subject,
			"authMethods", accountClientsDTO.AuthMethods,
		)
		return dtos.AccountCredentialsDTO{}, exceptions.NewForbiddenError()
	}
	if opts.claims.Issuer == "" ||
		!utils.IsValidURL(opts.claims.Issuer) ||
		!slices.Contains(accountClientsDTO.Issuers, utils.ProcessURL(opts.claims.Issuer)) {
		logger.WarnContext(ctx, "JWT Bearer token issuer is not allowed", "issuer", opts.claims.Issuer)
		return dtos.AccountCredentialsDTO{}, exceptions.NewForbiddenError()
	}
	if len(opts.claims.Audience) != 1 ||
		utils.ProcessURL(opts.claims.Audience[0]) != fmt.Sprintf("https://%s", opts.backendDomain) {
		logger.WarnContext(ctx, "JWT Bearer token audience is not allowed",
			"audience", opts.claims.Audience,
		)
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	now := time.Now()
	if opts.claims.ExpiresAt == nil || opts.claims.ExpiresAt.Before(now) {
		logger.WarnContext(ctx, "JWT Bearer token is expired", "expiresAt", opts.claims.ExpiresAt)
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	expAtUnix := opts.claims.ExpiresAt.Unix()
	if opts.claims.IssuedAt != nil {
		if opts.claims.IssuedAt.Before(now.Add(-time.Minute * 2)) {
			logger.WarnContext(ctx, "JWT Bearer token is issued too long ago",
				"issuedAt", opts.claims.IssuedAt,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if opts.claims.IssuedAt.After(now) {
			logger.WarnContext(ctx, "JWT Bearer token is in the future", "issuedAt", opts.claims.IssuedAt)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if expAtUnix-opts.claims.IssuedAt.Unix() > bearerJWTMaxValiditySecs {
			logger.WarnContext(ctx, "JWT Bearer token has a validity period greater than 5 minutes",
				"expiresAt", opts.claims.ExpiresAt, "issuedAt", opts.claims.IssuedAt,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
	}
	if expAtUnix-now.Unix() > bearerJWTMaxValiditySecs {
		logger.WarnContext(ctx, "JWT Bearer token has a validity period greater than 5 minutes", "expiresAt", opts.claims.ExpiresAt)
		return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Account JWT Bearer token is valid")
	return accountClientsDTO, nil
}

type generateClientCredentialsAuthenticationOptions struct {
	requestID       string
	accountPublicID uuid.UUID
	accountVersion  int32
	clientID        string
	scopes          []string
}

func (s *Services) generateClientCredentialsAuthentication(
	ctx context.Context,
	opts generateClientCredentialsAuthenticationOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthLocation, "generateClientCredentialsAuthentication").With(
		"accountPublicID", opts.accountPublicID,
		"clientID", opts.clientID,
		"scopes", opts.scopes,
	)
	logger.InfoContext(ctx, "Generating client credentials authentication...")

	token, err := s.jwt.CreateAccessToken(tokens.AccountAccessTokenOptions{
		PublicID:     opts.accountPublicID,
		Version:      opts.accountVersion,
		Scopes:       opts.scopes,
		TokenSubject: opts.clientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token:     token,
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyTypeClientCredentials,
			TTL:       s.jwt.GetAccountCredentialsTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, opts.requestID),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, opts.requestID),
		StoreFN:         s.BuildUpdateJWKDEKFn(ctx, opts.requestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign access token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Client credentials authentication generated successfully")
	return dtos.NewAuthDTO(signedToken, s.jwt.GetAccountCredentialsTTL()), nil
}

type JWTBearerAccountLoginOptions struct {
	RequestID     string
	Token         string
	Scopes        []string
	BackendDomain string
}

func (s *Services) JWTBearerAccountLogin(
	ctx context.Context,
	opts JWTBearerAccountLoginOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "JWTBearerAccountLogin")
	logger.InfoContext(ctx, "JWT Bearer account logging in...")

	claims, kid, err := s.jwt.VerifyJWTBearerGrantToken(opts.Token, s.BuildGetClientCredentialsKeyPublicJWKFn(
		ctx,
		BuildGetClientCredentialsKeyFnOptions{
			RequestID: opts.RequestID,
			Usage:     database.CredentialsUsageAccount,
		},
	))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify JWT Bearer", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountClientsDTO, serviceErr := s.validateAccountJWTGrantToken(ctx, validateAccountJWTClaimsOptions{
		requestID:     opts.RequestID,
		claims:        claims,
		backendDomain: opts.BackendDomain,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to validate JWT Bearer token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	account, err := s.database.FindAccountCredentialsKeyAccountByAccountCredentialIDAndJWKKID(
		ctx,
		database.FindAccountCredentialsKeyAccountByAccountCredentialIDAndJWKKIDParams{
			AccountCredentialsID: accountClientsDTO.ID(),
			JwkKid:               kid,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found by account credentials ID and JWK kid",
				"accountCredentialsId", accountClientsDTO.ID(),
				"jwkKid", kid,
			)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to find account by account credentials ID and JWK kid", "error", err)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.generateClientCredentialsAuthentication(ctx, generateClientCredentialsAuthenticationOptions{
		requestID:       opts.RequestID,
		accountPublicID: account.PublicID,
		accountVersion:  account.Version,
		clientID:        accountClientsDTO.ClientID,
		scopes:          mapDefaultAccountScopes(opts.Scopes, accountClientsDTO.Scopes),
	})
}

type processAccountClientSecretOptions struct {
	requestID    string
	clientSecret string
}

func (s *Services) processAccountClientSecret(
	ctx context.Context,
	opts processAccountClientSecretOptions,
) (string, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthLocation, "processAccountClientSecret")
	logger.InfoContext(ctx, "Processing account client secret...")
	secret := strings.TrimSpace(opts.clientSecret)
	if secret == "" {
		logger.WarnContext(ctx, "Client secret is empty")
		return "", "", exceptions.NewUnauthorizedError()
	}

	parts := strings.Split(secret, ".")
	if len(parts) != 2 {
		logger.WarnContext(ctx, "Client secret must be in the format 'secretID.secretValue'")
		return "", "", exceptions.NewUnauthorizedError()
	}

	idLen := len(parts[0])
	if idLen != 22 {
		logger.WarnContext(ctx, "Client secret ID must be 22 characters long", "secretIdLength", idLen)
		return "", "", exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Successfully processed account client secret", "secretID", parts[0])
	return parts[0], parts[1], nil
}

type ClientCredentialsAccountLoginOptions struct {
	RequestID    string
	ClientID     string
	ClientSecret string
	Issuer       string
	Scopes       []string
	AuthMethod   database.AuthMethod
}

func (s *Services) ClientCredentialsAccountLogin(
	ctx context.Context,
	opts ClientCredentialsAccountLoginOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "ClientCredentialsAccountLogin").With(
		"clientID", opts.ClientID,
		"issuer", opts.Issuer,
		"authenticationMethod", opts.AuthMethod,
	)
	logger.InfoContext(ctx, "Client credentials account logging in...")

	secretID, secret, serviceErr := s.processAccountClientSecret(ctx, processAccountClientSecretOptions{
		requestID:    opts.RequestID,
		clientSecret: opts.ClientSecret,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to process account client secret", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accountClientsDTO, serviceErr := s.GetAccountCredentialsByPublicID(ctx, GetAccountCredentialsByPublicIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account credentials by public ID", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}
	if slices.Contains(accountClientsDTO.AuthMethods, opts.AuthMethod) {
		logger.WarnContext(ctx, "Account credentials does not support client credentials login",
			"authMethods", accountClientsDTO.AuthMethods,
		)
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()

	}
	if !slices.Contains(accountClientsDTO.Issuers, utils.ProcessURL(opts.Issuer)) {
		logger.WarnContext(ctx, "Client credentials issuer is not allowed", "issuer", opts.Issuer)
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}

	secretEnt, err := s.database.FindValidAccountCredentialSecretByAccountCredentialIDAndCredentialsSecretID(
		ctx,
		database.FindValidAccountCredentialSecretByAccountCredentialIDAndCredentialsSecretIDParams{
			AccountCredentialsID: accountClientsDTO.ID(),
			SecretID:             secretID,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account credentials secret not found",
				"accountCredentialsId", accountClientsDTO.ID(),
				"secretID", secretID,
			)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to find account credentials secret", "error", err)
		return dtos.AuthDTO{}, serviceErr
	}

	verified, err := utils.Argon2CompareHash(secret, secretEnt.ClientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare account credentials secret", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !verified {
		logger.WarnContext(ctx, "Account credentials secret is invalid")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        accountClientsDTO.AccountID(),
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found by account credentials ID",
				"accountCredentialsId", accountClientsDTO.ID(),
			)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get account by account credentials ID", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	return s.generateClientCredentialsAuthentication(ctx, generateClientCredentialsAuthenticationOptions{
		requestID:       opts.RequestID,
		accountPublicID: accountDTO.PublicID,
		accountVersion:  accountDTO.Version(),
		clientID:        accountClientsDTO.ClientID,
		scopes:          mapDefaultAccountScopes(opts.Scopes, accountClientsDTO.Scopes),
	})
}
