// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthLocation string = "oauth"

	// Maximum validity of a bearer JWT, set to 5 minutes (300 seconds)
	bearerJWTMaxValiditySecs int64 = 300

	// Maximum JWT bearer issuance tolerance, set to 2 minutes
	bearerJWTMaxIssuanceTolerance time.Duration = 2 * time.Minute
)

var oauthScopes = []oauth.Scope{oauth.ScopeProfile}

type AccountOAuthURLOptions struct {
	RequestID       string
	Provider        string
	RedirectURL     string
	Challenge       string
	ChallengeMethod string
	State           string
}

func (s *Services) AccountOAuthURL(ctx context.Context, opts AccountOAuthURLOptions) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "AccountOAuthURL").With(
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Getting OAuth authorization url...")

	challenge, serviceErr := hashChallenge(opts.Challenge, opts.ChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map challenge method", "serviceErr", serviceErr)
		return "", serviceErr
	}

	authUrlOpts := oauth.AuthorizationURLOptions{
		RequestID:   opts.RequestID,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var oauthUrl, state string
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
		return "", exceptions.NewInternalServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get authorization url or State", "error", serviceErr)
		return "", serviceErr
	}

	if err := s.cache.SaveOAuthStateData(ctx, cache.SaveOAuthStateDataOptions{
		RequestID:    opts.RequestID,
		State:        state,
		Provider:     opts.Provider,
		RequestState: opts.State,
		Challenge:    challenge,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache State", "error", err)
		return "", exceptions.NewInternalServerError()
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
) (string, cache.OAuthStateData, *exceptions.ServiceError) {
	stateData, found, err := s.cache.GetOAuthState(ctx, cache.GetOAuthStateOptions{
		RequestID: opts.requestID,
		State:     opts.state,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth State", "error", err)
		return "", cache.OAuthStateData{}, exceptions.NewInternalServerError()
	}
	if !found {
		logger.WarnContext(ctx, "OAuth State is invalid")
		return "", cache.OAuthStateData{}, exceptions.NewValidationError("OAuth State is invalid")
	}
	if stateData.Provider != opts.provider {
		logger.WarnContext(ctx, "OAuth State provider does not match",
			"expectedProvider", opts.provider,
			"actualProvider", stateData.Provider,
		)
		return "", cache.OAuthStateData{}, exceptions.NewValidationError("OAuth State provider does not match")
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
		return "", cache.OAuthStateData{}, exceptions.NewInternalServerError()
	}
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get oauth access token", "error", serviceErr)
		return "", cache.OAuthStateData{}, serviceErr
	}

	logger.InfoContext(ctx, "Got access token successfully")
	return token, stateData, nil
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
		return oauth.UserData{}, exceptions.NewInternalServerError()
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
	requestID  string
	provider   string
	email      string
	givenName  string
	familyName string
}

func (s *Services) saveExtAccount(
	ctx context.Context,
	logger *slog.Logger,
	opts saveExtAccount,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	accountDto, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.requestID,
		Email:     opts.email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account by email", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewInternalServerError()
		}

		accountDto, serviceErr := s.CreateAccount(ctx, CreateAccountOptions{
			RequestID:  opts.requestID,
			GivenName:  opts.givenName,
			FamilyName: opts.familyName,
			Email:      opts.email,
			Provider:   opts.provider,
			Password:   "",
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create account", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewInternalServerError()
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

	token, stateData, serviceErr := s.extOAuthToken(ctx, logger, extOAuthTokenOptions{
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

	code, err := s.cache.GenerateOAuthCode(ctx, cache.GenerateOAuthCodeOptions{
		RequestID:  opts.RequestID,
		Email:      userData.Email,
		GivenName:  userData.FirstName,
		FamilyName: userData.LastName,
		Provider:   opts.Provider,
		Challenge:  stateData.Challenge,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth code", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	queryParams := make(url.Values)
	queryParams.Add("code", code)
	queryParams.Add("state", stateData.RequestState)
	logger.InfoContext(ctx, "Generated OAuth code successfully")
	return queryParams.Encode(), nil
}

type verifyOAuthChallengeOptions struct {
	requestID         string
	challenge         string
	challengeVerifier string
}

func (s *Services) verifyOAuthChallenge(
	ctx context.Context,
	opts verifyOAuthChallengeOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, oauthLocation, "verifyOAuthChallenge")

	hashedVerifier := utils.Sha256HashBase64([]byte(opts.challengeVerifier))
	if !utils.CompareSha256([]byte(hashedVerifier), []byte(opts.challenge)) {
		logger.WarnContext(ctx, "OAuth code challenge verification failed",
			"challenge", opts.challenge,
			"challengeVerifier", opts.challengeVerifier,
		)
		return exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "OAuth code challenge verified successfully")
	return nil
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

	stateData, found, err := s.cache.GetOAuthState(ctx, cache.GetOAuthStateOptions{
		RequestID: opts.RequestID,
		State:     opts.State,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth State", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
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

	ok, serviceErr := s.oauthProviders.ValidateAppleIDToken(ctx, oauth.ValidateAppleIDTokenOptions{
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

	code, err := s.cache.GenerateOAuthCode(ctx, cache.GenerateOAuthCodeOptions{
		RequestID:  opts.RequestID,
		Email:      opts.Email,
		GivenName:  opts.FirstName,
		FamilyName: opts.LastName,
		Provider:   AuthProviderApple,
		Challenge:  stateData.Challenge,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth code", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	queryParams := make(url.Values)
	queryParams.Add("code", code)
	queryParams.Add("state", stateData.RequestState)
	logger.InfoContext(ctx, "Generated OAuth code successfully")
	return queryParams.Encode(), nil
}

type OAuthLoginAccountOptions struct {
	RequestID         string
	Provider          string
	Code              string
	ChallengeVerifier string
}

func (s *Services) OAuthLoginAccount(
	ctx context.Context,
	opts OAuthLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "OAuthLoginAccount")
	logger.InfoContext(ctx, "OAuth account logging in...")

	oauthData, ok, err := s.cache.VerifyOAuthCode(ctx, cache.VerifyOAuthCodeOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify OAuth Code", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth Code verification failed")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if oauthData.Provider != opts.Provider {
		logger.WarnContext(ctx, "OAuth Code provider does not match",
			"expectedProvider", opts.Provider,
			"actualProvider", oauthData.Provider,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if serviceErr := s.verifyOAuthChallenge(ctx, verifyOAuthChallengeOptions{
		requestID:         opts.RequestID,
		challenge:         oauthData.Challenge,
		challengeVerifier: opts.ChallengeVerifier,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to verify OAuth challenge", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.saveExtAccount(ctx, logger, saveExtAccount{
		requestID:  opts.RequestID,
		provider:   AuthProviderApple,
		email:      oauthData.Email,
		givenName:  oauthData.GivenName,
		familyName: oauthData.FamilyName,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to save external account", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
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
	scopesMap := utils.SliceToHashSet(scopesSlice)
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
			database.AccountCredentialsScopeAccountCredentialsWrite, database.AccountCredentialsScopeProfile,
			database.AccountCredentialsScopeAccountAuthProvidersRead, database.AccountCredentialsScopeEmail:
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

func (s *Services) validateAccountJWTClaims(
	ctx context.Context,
	opts validateAccountJWTClaimsOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthLocation, "validateAccountJWTClaims")
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

	if accountClientsDTO.TokenEndpointAuthMethod != database.AuthMethodPrivateKeyJwt &&
		accountClientsDTO.TokenEndpointAuthMethod != database.AuthMethodClientSecretJwt {
		logger.InfoContext(ctx, "Account credentials does not support JWT Bearer login",
			"clientID", opts.claims.Subject,
			"authMethods", accountClientsDTO.TokenEndpointAuthMethod,
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
		if opts.claims.IssuedAt.Before(now.Add(-bearerJWTMaxIssuanceTolerance)) {
			logger.WarnContext(ctx, "JWT Bearer token was issued too long ago",
				"iat", opts.claims.IssuedAt,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if opts.claims.IssuedAt.After(now) {
			logger.WarnContext(ctx, "JWT Bearer token is in the future", "iat", opts.claims.IssuedAt)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if opts.claims.NotBefore != nil {
			if opts.claims.NotBefore.After(now) {
				logger.WarnContext(ctx, "JWT Bearer token is not valid yet",
					"iat", opts.claims.IssuedAt, "nbf", opts.claims.NotBefore,
				)
				return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
			}
			if opts.claims.NotBefore.Unix() < opts.claims.IssuedAt.Unix() {
				logger.WarnContext(ctx, "JWT Bearer token nbf is before iat",
					"nbf", opts.claims.NotBefore, "iat", opts.claims.IssuedAt,
				)
				return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
			}
		}
		if expAtUnix-opts.claims.IssuedAt.Unix() > bearerJWTMaxValiditySecs {
			logger.WarnContext(ctx, "JWT Bearer token has a validity period greater than 5 minutes",
				"exp", opts.claims.ExpiresAt, "iat", opts.claims.IssuedAt,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
	} else if opts.claims.NotBefore != nil {
		if opts.claims.NotBefore.Before(now.Add(-bearerJWTMaxIssuanceTolerance)) {
			logger.WarnContext(ctx, "JWT Bearer token was issued too long ago",
				"nbf", opts.claims.NotBefore,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if opts.claims.NotBefore.After(now) {
			logger.WarnContext(ctx, "JWT Bearer token is not valid yet", "nbf", opts.claims.NotBefore)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
		if expAtUnix-opts.claims.NotBefore.Unix() > bearerJWTMaxValiditySecs {
			logger.WarnContext(ctx, "JWT Bearer token has a validity period greater than 5 minutes",
				"exp", opts.claims.ExpiresAt, "nbf", opts.claims.NotBefore,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
	} else {
		if expAtUnix-now.Unix() > bearerJWTMaxValiditySecs {
			logger.WarnContext(ctx, "JWT Bearer token has a validity period greater than 5 minutes",
				"exp", opts.claims.ExpiresAt,
			)
			return dtos.AccountCredentialsDTO{}, exceptions.NewUnauthorizedError()
		}
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
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
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

	claims, cryptoSuite, kid, err := s.jwt.VerifyJWTBearerGrantToken(
		opts.Token,
		s.BuildGetClientCredentialsKeyPublicJWKFn(
			ctx,
			BuildGetClientCredentialsKeyFnOptions{
				RequestID: opts.RequestID,
				Usage:     database.CredentialsUsageAccount,
			},
		),
		s.BuildGetAccountClientCredentialsSecretFn(ctx, opts.RequestID),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify JWT Bearer", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountClientsDTO, serviceErr := s.validateAccountJWTClaims(ctx, validateAccountJWTClaimsOptions{
		requestID:     opts.RequestID,
		claims:        claims,
		backendDomain: opts.BackendDomain,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to validate JWT Bearer token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	var account database.Account
	switch cryptoSuite {
	case utils.SupportedCryptoSuiteES256, utils.SupportedCryptoSuiteEd25519:
		account, err = s.database.FindAccountCredentialsKeyAccountByAccountCredentialIDAndJWKKID(
			ctx,
			database.FindAccountCredentialsKeyAccountByAccountCredentialIDAndJWKKIDParams{
				AccountCredentialsID: accountClientsDTO.ID(),
				JwkKid:               kid,
			},
		)
	case utils.SupportedCryptoSuiteHS256:
		account, err = s.database.FindAccountCredentialsSecretAccountByAccountCredentialIDAndSecretID(
			ctx,
			database.FindAccountCredentialsSecretAccountByAccountCredentialIDAndSecretIDParams{
				AccountCredentialsID: accountClientsDTO.ID(),
				SecretID:             kid,
			},
		)
	default:
		logger.ErrorContext(ctx, "Unsupported crypto suite", "cryptoSuite", cryptoSuite)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
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
	Scopes       []string
	AuthMethod   database.AuthMethod
}

func (s *Services) ClientCredentialsAccountLogin(
	ctx context.Context,
	opts ClientCredentialsAccountLoginOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "ClientCredentialsAccountLogin").With(
		"clientID", opts.ClientID,
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
	if accountClientsDTO.TokenEndpointAuthMethod != opts.AuthMethod {
		logger.WarnContext(ctx, "Account credentials does not support client credentials login",
			"authMethods", accountClientsDTO.TokenEndpointAuthMethod,
		)
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
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
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
