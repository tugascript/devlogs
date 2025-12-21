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

	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/services/templates"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const oauthDynamicRegistrationLocation string = "oauth_dynamic_registration"

const (
	oauthDynamicRegistrationIATPath     string = paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken
	oauthDynamicRegistrationIATAuthPath string = oauthDynamicRegistrationIATPath + paths.OAuthAuth
)

type buildOAuthDynamicRegistrationIATLoginURLOptions struct {
	accClientID     string
	domain          string
	state           string
	challenge       string
	challengeMethod string
	redirectURI     string
}

func buildOAuthDynamicRegistrationIATLoginURL(opts buildOAuthDynamicRegistrationIATLoginURLOptions) string {
	queryParams := make(url.Values)
	queryParams.Add("client_id", opts.domain)
	queryParams.Add("response_type", "code")
	queryParams.Add("state", opts.state)
	queryParams.Add("code_challenge", opts.challenge)
	if opts.challengeMethod != "" {
		queryParams.Add("code_challenge_method", opts.challengeMethod)
	}
	return oauthDynamicRegistrationIATPath + "/" + opts.accClientID + paths.OAuthAuth + paths.AuthLogin + "?" + queryParams.Encode()
}

type buildOAuthDynamicRegistrationIATCallbackURLOptions struct {
	redirectURI   string
	code          string
	state         string
	backendDomain string
}

func buildOAuthDynamicRegistrationIATCallbackURL(opts buildOAuthDynamicRegistrationIATCallbackURLOptions) string {
	queryParams := make(url.Values)
	queryParams.Add("code", opts.code)
	queryParams.Add("state", opts.state)
	queryParams.Add("iss", "https://"+opts.backendDomain)
	return opts.redirectURI + "?" + queryParams.Encode()
}

type generateOAuthDynamicRegistrationIATCallbackOptions struct {
	requestID       string
	clientID        string
	accountPublicID uuid.UUID
	accountVersion  int32
	challenge       string
	domain          string
	redirectURI     string
	state           string
	backendDomain   string
}

func (s *Services) generateOAuthDynamicRegistrationIATCallback(
	ctx context.Context,
	opts generateOAuthDynamicRegistrationIATCallbackOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.requestID,
		oauthDynamicRegistrationLocation,
		"generateOAuthDynamicRegistrationIATCallback",
	).With(
		"clientId", opts.clientID,
		"accountPublicId", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Generating OAuth dynamic registration IAT callback...")

	code, err := s.cache.GenerateAccountCredentialsRegistrationIATCode(
		ctx,
		cache.GenerateAccountCredentialsRegistrationIATCodeOptions{
			RequestID:       opts.requestID,
			ClientID:        opts.clientID,
			AccountPublicID: opts.accountPublicID,
			AccountVersion:  opts.accountVersion,
			Challenge:       opts.challenge,
			Domain:          opts.domain,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate account credentials registration IAT code", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return buildOAuthDynamicRegistrationIATCallbackURL(buildOAuthDynamicRegistrationIATCallbackURLOptions{
		redirectURI:   opts.redirectURI,
		code:          code,
		state:         opts.state,
		backendDomain: opts.backendDomain,
	}), nil
}

func mapDomainUsageFromHostExistence(host string) database.DynamicRegistrationUsage {
	if host != "" {
		return database.DynamicRegistrationUsageApp
	}

	return database.DynamicRegistrationUsageAccount
}

type checkDynamicClientRegistrationDomainUsabilityOptions struct {
	requestID       string
	accountUsername string
	domain          string
}

func (s *Services) checkDynamicRegistrationDomainUsability(
	ctx context.Context,
	opts checkDynamicClientRegistrationDomainUsabilityOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, dynamicRegistrationDomainsLocation, "checkDynamicRegistrationDomainUsability").With(
		"accountUsername", opts.accountUsername,
	)
	logger.InfoContext(ctx, "Checking dynamic registration domain usability")

	usage := mapDomainUsageFromHostExistence(opts.accountUsername)
	domains := breakDomainIntoAllSubdomains(opts.domain)
	var count int64
	var err error
	if len(domains) > 1 {
		count, err = s.database.CountDynamicRegistrationDomainsByDomainsAndUsages(
			ctx,
			database.CountDynamicRegistrationDomainsByDomainsAndUsagesParams{
				Domains: domains,
				Usages:  []database.DynamicRegistrationUsage{usage},
			},
		)
	} else {
		count, err = s.database.CountDynamicRegistrationDomainsByDomainAndUsages(
			ctx,
			database.CountDynamicRegistrationDomainsByDomainAndUsagesParams{
				Domain: opts.domain,
				Usages: []database.DynamicRegistrationUsage{usage},
			},
		)
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count dynamic registration domains by domain and usages", "error", err)
		return exceptions.FromDBError(err)
	}
	if count == 0 {
		logger.WarnContext(ctx, "Domain not registered for dynamic registration")
		return exceptions.NewForbiddenError()
	}

	return nil
}

type oauthDynamicRegistrationIATAuthOptions struct {
	requestID       string
	challenge       string
	challengeMethod string
	domain          string
	redirectURI     string
	state           string
	hostUsername    string
}

func (s *Services) oauthDynamicRegistrationIATAuth(
	ctx context.Context,
	opts oauthDynamicRegistrationIATAuthOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.requestID,
		oauthDynamicRegistrationLocation,
		"oauthDynamicRegistrationIATAuth",
	).With(
		"domain", opts.domain,
		"redirectUri", opts.redirectURI,
		"hostUsername", opts.hostUsername,
	)
	logger.InfoContext(ctx, "Handling OAuth dynamic registration IAT auth...")

	if serviceErr := s.checkDynamicRegistrationDomainUsability(
		ctx,
		checkDynamicClientRegistrationDomainUsabilityOptions{
			requestID:       opts.requestID,
			accountUsername: opts.hostUsername,
		},
	); serviceErr != nil {
		logger.InfoContext(ctx, "Dynamic registration domain not usable", "serviceError", serviceErr)
		return "", serviceErr
	}

	hashedChallenge, serviceErr := hashChallenge(opts.challenge, opts.challengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Invalid code challenge", "serviceError", serviceErr)
		return "", serviceErr
	}

	clientID, err := s.cache.SaveAccountCredentialsDynamicRegistrationIATAuth(
		ctx,
		cache.SaveAccountCredentialsDynamicRegistrationIATAuthOptions{
			Domain:      opts.domain,
			RequestID:   opts.requestID,
			State:       opts.state,
			RedirectURI: opts.redirectURI,
			Challenge:   hashedChallenge,
			Username:    opts.hostUsername,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return buildOAuthDynamicRegistrationIATLoginURL(buildOAuthDynamicRegistrationIATLoginURLOptions{
		accClientID:     clientID,
		domain:          opts.domain,
		state:           opts.state,
		challenge:       opts.challenge,
		challengeMethod: opts.challengeMethod,
		redirectURI:     opts.redirectURI,
	}), nil
}

type refreshTokenOAuthDynamicRegistrationIATLoginOptions struct {
	requestID       string
	refreshToken    string
	challenge       string
	challengeMethod string
	domain          string
	redirectURI     string
	state           string
	backendDomain   string
}

func (s *Services) refreshTokenOAuthDynamicRegistrationIATLogin(
	ctx context.Context,
	opts refreshTokenOAuthDynamicRegistrationIATLoginOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.requestID,
		oauthDynamicRegistrationLocation,
		"refreshTokenOAuthDynamicRegistrationIATLogin",
	).With(
		"domain", opts.domain,
		"redirectUri", opts.redirectURI,
	)
	logger.InfoContext(ctx, "Refreshing OAuth dynamic registration IAT callback...")

	data, err := s.jwt.VerifyRefreshToken(
		opts.refreshToken,
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyTypeRefresh,
		}),
	)
	if err != nil {
		logger.WarnContext(ctx, "Invalid refresh token", "error", err)
		return buildOAuthDynamicRegistrationIATLoginURL(buildOAuthDynamicRegistrationIATLoginURLOptions{
			domain:          opts.domain,
			state:           opts.state,
			challenge:       opts.challenge,
			challengeMethod: opts.challengeMethod,
			redirectURI:     opts.redirectURI,
		}), nil
	}

	if !slices.ContainsFunc(data.Scopes, func(s string) bool {
		return s == tokens.AccountScopeAdmin || s == tokens.AccountScopeCredentialsWrite
	}) {
		logger.WarnContext(ctx, "Refresh token missing offline_access scope")
		return buildOAuthDynamicRegistrationIATLoginURL(buildOAuthDynamicRegistrationIATLoginURLOptions{
			domain:          opts.domain,
			state:           opts.state,
			challenge:       opts.challenge,
			challengeMethod: opts.challengeMethod,
			redirectURI:     opts.redirectURI,
		}), nil
	}

	blt, err := s.database.GetRevokedToken(ctx, data.TokenID)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get blacklisted token", "error", err)
			return "", exceptions.NewInternalServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is revoked", "revokedAt", blt.CreatedAt)
		return buildOAuthDynamicRegistrationIATLoginURL(buildOAuthDynamicRegistrationIATLoginURLOptions{
			domain:          opts.domain,
			state:           opts.state,
			challenge:       opts.challenge,
			challengeMethod: opts.challengeMethod,
			redirectURI:     opts.redirectURI,
		}), nil
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.requestID,
		PublicID:  data.AccountClaims.AccountID,
		Version:   data.AccountClaims.AccountVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound && serviceErr.Code != exceptions.CodeUnauthorized {
			logger.ErrorContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
			return "", serviceErr
		}

		logger.WarnContext(ctx, "Account not found or version mismatch", "serviceError", serviceErr)
		return s.oauthDynamicRegistrationIATAuth(ctx, oauthDynamicRegistrationIATAuthOptions{
			requestID:       opts.requestID,
			challenge:       opts.challenge,
			challengeMethod: opts.challengeMethod,
			domain:          opts.domain,
			redirectURI:     opts.redirectURI,
			state:           opts.state,
		})
	}

	hashedChallenge, serviceErr := hashChallenge(opts.challenge, opts.challengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Invalid code challenge", "serviceError", serviceErr)
		return "", serviceErr
	}

	cbURL, serviceErr := s.generateOAuthDynamicRegistrationIATCallback(
		ctx,
		generateOAuthDynamicRegistrationIATCallbackOptions{
			requestID:       opts.requestID,
			clientID:        utils.Base62UUID(),
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			challenge:       hashedChallenge,
			domain:          opts.domain,
			redirectURI:     opts.redirectURI,
			state:           opts.state,
			backendDomain:   opts.backendDomain,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth dynamic registration IAT callback", "serviceErr", serviceErr)
		return "", serviceErr
	}

	return cbURL, nil
}

type InitiateOAuthDynamicRegistrationIATAuthOptions struct {
	RequestID       string
	Domain          string
	State           string
	SessionKey      string
	RefreshToken    string
	Challenge       string
	ChallengeMethod string
	RedirectURI     string
	BackendDomain   string
	HostUsername    string
}

func (s *Services) InitiateOAuthDynamicRegistrationIATAuth(
	ctx context.Context,
	opts InitiateOAuthDynamicRegistrationIATAuthOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		oauthDynamicRegistrationLocation,
		"InitiateOAuthDynamicRegistrationIATAuth",
	).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.InfoContext(ctx, "Starting OAuth dynamic registration IAT authorization...")

	if opts.SessionKey == "" {
		if opts.RefreshToken == "" {
			logger.InfoContext(ctx, "No session key or refresh token provided, redirecting to login")
			return s.oauthDynamicRegistrationIATAuth(ctx, oauthDynamicRegistrationIATAuthOptions{
				requestID:       opts.RequestID,
				challenge:       opts.Challenge,
				challengeMethod: opts.ChallengeMethod,
				domain:          opts.Domain,
				redirectURI:     opts.RedirectURI,
				state:           opts.State,
				hostUsername:    opts.HostUsername,
			})
		}

		logger.InfoContext(ctx, "No session key provided, attempting to refresh with refresh token")
		return s.refreshTokenOAuthDynamicRegistrationIATLogin(
			ctx,
			refreshTokenOAuthDynamicRegistrationIATLoginOptions{
				requestID:       opts.RequestID,
				refreshToken:    opts.RefreshToken,
				challenge:       opts.Challenge,
				challengeMethod: opts.ChallengeMethod,
				domain:          opts.Domain,
				redirectURI:     opts.RedirectURI,
				state:           opts.State,
				backendDomain:   opts.BackendDomain,
			},
		)
	}

	data, credsClientID, verified, found, err := s.cache.VerifyAccountCredentialsRegistrationSessionKey(
		ctx,
		cache.VerifyAccountCredentialsRegistrationSessionKeyOptions{
			RequestID:  opts.RequestID,
			SessionKey: opts.SessionKey,
			Domain:     opts.Domain,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account credentials registration session key", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.WarnContext(ctx, "Account credentials registration session key not found")
		return "", exceptions.NewUnauthorizedError()
	}

	if !verified {
		logger.WarnContext(ctx, "Account credentials registration session key is not verified")
		return "", exceptions.NewUnauthorizedError()
	}

	if err := s.cache.DeleteAccountCredentialsRegistrationSessionKey(
		ctx,
		cache.DeleteAccountCredentialsRegistrationSessionKeyOptions{
			RequestID: opts.RequestID,
			ClientID:  credsClientID,
		},
	); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account credentials registration session key", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountPublicID,
		Version:   data.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
		return "", serviceErr
	}

	hashedChallenge, serviceErr := hashChallenge(opts.Challenge, opts.ChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Invalid code challenge", "serviceError", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Successfully verified account credentials registration IAT session key, creating code...")
	cbURL, serviceErr := s.generateOAuthDynamicRegistrationIATCallback(
		ctx,
		generateOAuthDynamicRegistrationIATCallbackOptions{
			requestID:       opts.RequestID,
			clientID:        credsClientID,
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			challenge:       hashedChallenge,
			domain:          opts.Domain,
			redirectURI:     opts.RedirectURI,
			state:           opts.State,
			backendDomain:   opts.BackendDomain,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth dynamic registration IAT callback", "serviceErr", serviceErr)
		return "", serviceErr
	}

	return cbURL, nil
}

type OAuthDynamicRegistrationIATAuthRenderOptions struct {
	RequestID           string
	ACCClientID         string
	State               string
	Domain              string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
}

func (s *Services) OAuthDynamicRegistrationIATAuthRender(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATAuthRenderOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		oauthDynamicRegistrationLocation,
		"OAuthDynamicRegistrationIATAuthRender",
	).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.InfoContext(ctx, "Starting OAuth dynamic registration IAT authorization html render...")

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(
		ctx,
		cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
			RequestID: opts.RequestID,
			ClientID:  opts.ACCClientID,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.WarnContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", exceptions.NewForbiddenError()
	}

	if data.Domain != opts.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", data.Domain)
		return "", exceptions.NewUnauthorizedError()
	}
	if data.State != opts.State {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", exceptions.NewUnauthorizedError()
	}
	if data.RedirectURI != opts.RedirectURI {
		logger.WarnContext(ctx, "OAuth Redirect URI does not match")
		return "", exceptions.NewUnauthorizedError()
	}

	csrfToken, err := s.cache.SaveAccountCredentialsDynamicRegistrationIATLoginCSRF(
		ctx,
		cache.SaveAccountCredentialsDynamicRegistrationIATLoginCSRFOptions{
			RequestID: opts.RequestID,
			ClientID:  opts.ACCClientID,
			Domain:    opts.Domain,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT auth CSRF token", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	loginHTML, err := templates.BuildAccountDynamicRegistrationIATAuthTemplate(
		templates.AccountDynamicRegistrationIATAuthOptions{
			ACCClientID:         opts.ACCClientID,
			CSRFToken:           csrfToken,
			Domain:              opts.Domain,
			State:               opts.State,
			CodeChallenge:       opts.CodeChallenge,
			CodeChallengeMethod: opts.CodeChallengeMethod,
			RedirectURI:         opts.RedirectURI,
			AppleEnabled:        s.oauthProviders.IsAppleEnabled(),
			FacebookEnabled:     s.oauthProviders.IsFacebookEnabled(),
			GitHubEnabled:       s.oauthProviders.IsGitHubEnabled(),
			GoogleEnabled:       s.oauthProviders.IsGoogleEnabled(),
			MicrosoftEnabled:    s.oauthProviders.IsMicrosoftEnabled(),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build account dynamic registration IAT auth template", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return loginHTML, nil
}

type OAuthDynamicRegistrationIATAuthReRenderOptions struct {
	RequestID           string
	Errors              []string
	CSRFToken           string
	ACCClientID         string
	State               string
	Domain              string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
}

func (s *Services) OAuthDynamicRegistrationIATAuthReRender(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATAuthReRenderOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		oauthDynamicRegistrationLocation,
		"OAuthDynamicRegistrationIATAuthReRender",
	).With(
		"clientId", opts.ACCClientID,
		"redirectUri", opts.RedirectURI,
	)
	logger.InfoContext(ctx, "Re-rendering OAuth dynamic registration IAT authorization html...")

	loginHTML, err := templates.BuildAccountDynamicRegistrationIATAuthTemplate(
		templates.AccountDynamicRegistrationIATAuthOptions{
			Errors:              opts.Errors,
			ACCClientID:         opts.ACCClientID,
			CSRFToken:           opts.CSRFToken,
			Domain:              opts.Domain,
			State:               opts.State,
			CodeChallenge:       opts.CodeChallenge,
			CodeChallengeMethod: opts.CodeChallengeMethod,
			RedirectURI:         opts.RedirectURI,
			AppleEnabled:        s.oauthProviders.IsAppleEnabled(),
			FacebookEnabled:     s.oauthProviders.IsFacebookEnabled(),
			GitHubEnabled:       s.oauthProviders.IsGitHubEnabled(),
			GoogleEnabled:       s.oauthProviders.IsGoogleEnabled(),
			MicrosoftEnabled:    s.oauthProviders.IsMicrosoftEnabled(),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build account dynamic registration IAT auth template", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return loginHTML, nil
}

type OAuthDynamicRegistrationIATLoginOptions struct {
	RequestID           string
	ACCClientID         string
	Domain              string
	CSRFToken           string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
	RedirectURI         string
	Email               string
	Password            string
	BackendDomain       string
}

func (s *Services) OAuthDynamicRegistrationIATLogin(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATLoginOptions,
) (string, string, bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationLocation, "OAuthDynamicRegistrationIATLoginPost").With(
		"clientId", opts.ACCClientID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Logging in with OAuth dynamic registration IAT...")

	validCSRF, err := s.cache.VerifyAccountCredentialsDynamicRegistrationIATLoginCSRF(
		ctx,
		cache.VerifyAccountCredentialsDynamicRegistrationIATLoginCSRFOptions{
			RequestID: opts.RequestID,
			ClientID:  opts.ACCClientID,
			Domain:    opts.Domain,
			CSRFToken: opts.CSRFToken,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account credentials dynamic registration IAT auth CSRF token", "error", err)
		return "", "", false, exceptions.NewInternalServerError()
	}
	if !validCSRF {
		logger.WarnContext(ctx, "Invalid CSRF token")
		return "", "", false, exceptions.NewForbiddenError()
	}

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(ctx, cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ACCClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", "", false, exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", "", false, exceptions.NewNotFoundError()
	}

	if data.Domain != opts.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", data.Domain)
		return "", "", false, exceptions.NewUnauthorizedError()
	}
	if data.State != opts.State {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", "", false, exceptions.NewUnauthorizedError()
	}
	if data.RedirectURI != opts.RedirectURI {
		logger.WarnContext(ctx, "OAuth Redirect URI does not match")
		return "", "", false, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.RequestID,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return "", "", false, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return "", "", false, exceptions.NewUnauthorizedError()
	}
	if _, err := s.database.FindAccountAuthProviderByAccountPublicIdAndProvider(
		ctx,
		database.FindAccountAuthProviderByAccountPublicIdAndProviderParams{
			AccountPublicID: accountDTO.PublicID,
			Provider:        database.AuthProviderLocal,
		},
	); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account auth provider", "error", err)
			return "", "", false, serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "error", err)
		return "", "", false, exceptions.NewUnauthorizedError()
	}

	passwordVerified, err := utils.Argon2CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return "", "", false, exceptions.NewInternalServerError()
	}
	if !passwordVerified {
		logger.WarnContext(ctx, "Passwords do not match")
		return "", "", false, exceptions.NewUnauthorizedError()
	}
	if !accountDTO.EmailVerified() {
		logger.InfoContext(ctx, "Account is not confirmed")
		return "", "", false, exceptions.NewForbiddenError()
	}

	default2FAConfig, serviceErr := s.getDefaultAccount2FAConfigInternal(ctx, getDefaultAccount2FAConfigInternalOptions{
		requestID:       opts.RequestID,
		accountPublicID: accountDTO.PublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get default 2FA config", "serviceError", serviceErr)
		return "", "", false, serviceErr
	}
	if default2FAConfig != nil {
		logger.InfoContext(ctx, "Two-Factor is enabled, proceeding to 2FA step")
		sessionID, err := s.cache.SaveAccountCredentialsDynamicRegistrationIAT2FA(
			ctx,
			cache.SaveAccountCredentialsDynamicRegistrationIAT2FAOptions{
				RequestID:       opts.RequestID,
				AccountPublicID: accountDTO.PublicID,
				AccountVersion:  accountDTO.Version(),
				RedirectURI:     opts.RedirectURI,
				Domain:          data.Domain,
				ClientID:        opts.ACCClientID,
				State:           data.State,
				TwoFAType:       string(default2FAConfig.TwoFactorType),
				TwoFATTL:        s.jwt.Get2FATTL(),
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT 2FA", "error", err)
			return "", "", false, exceptions.NewInternalServerError()
		}

		if default2FAConfig.TwoFactorType == database.TwoFactorTypeEmail {
			code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
				TTL:       s.jwt.Get2FATTL(),
			})
			if err != nil {
				logger.ErrorContext(ctx, "Failed to add two factor code", "error", err)
				return "", "", false, exceptions.NewInternalServerError()
			}

			if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
				RequestID: opts.RequestID,
				Email:     accountDTO.Email,
				Name:      accountDTO.GivenName,
				Code:      code,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to send two factor code email", "error", err)
				return "", "", false, exceptions.NewInternalServerError()
			}

			logger.InfoContext(ctx, "Sent two factor code email successfully")
		}

		if err := s.cache.DeleteAccountCredentialsDynamicRegistrationIATAuth(
			ctx,
			cache.DeleteAccountCredentialsDynamicRegistrationIATAuthOptions{
				RequestID: opts.RequestID,
				ClientID:  opts.ACCClientID,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account credentials dynamic registration IAT auth", "error", err)
			return "", "", false, exceptions.NewInternalServerError()
		}

		queryParams := make(url.Values)
		queryParams.Add("client_id", data.Domain)
		queryParams.Add("redirect_uri", opts.RedirectURI)
		queryParams.Add("state", data.State)
		queryParams.Add("code_challenge", opts.CodeChallenge)
		if opts.CodeChallengeMethod != "" {
			queryParams.Add("code_challenge_method", opts.CodeChallengeMethod)
		}
		return oauthDynamicRegistrationIATPath + "/" + opts.ACCClientID + paths.OAuthAuth +
			paths.AuthLogin + paths.Auth2FA + queryParams.Encode(), sessionID, false, nil
	}

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		Domain:          data.Domain,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
			return "", "", false, serviceErr
		}

		if err := s.cache.DeleteAccountCredentialsDynamicRegistrationIATAuth(
			ctx,
			cache.DeleteAccountCredentialsDynamicRegistrationIATAuthOptions{
				RequestID: opts.RequestID,
				ClientID:  opts.ACCClientID,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account credentials dynamic registration IAT auth", "error", err)
			return "", "", false, exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Account credentials registration domain not found")
		return "", "", false, exceptions.NewForbiddenError()
	}
	if !domainDTO.Verified {
		logger.ErrorContext(ctx, "Account credentials registration domain is not validCSRF")
		return "", "", false, exceptions.NewForbiddenError()
	}

	sessionKey, err := s.cache.CreateAccountCredentialsRegistrationSessionKey(
		ctx,
		cache.CreateAccountCredentialsRegistrationSessionKeyOptions{
			RequestID:       opts.RequestID,
			ClientID:        opts.ACCClientID,
			Domain:          opts.Domain,
			AccountPublicID: accountDTO.PublicID,
			AccountVersion:  accountDTO.Version(),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account credentials registration session", "error", err)
		return "", "", false, exceptions.NewInternalServerError()
	}

	return oauthDynamicRegistrationIATAuthPath, sessionKey, true, nil
}

type OAuthDynamicRegistrationIAT2FARenderOptions struct {
	RequestID       string
	Domain          string
	ACCClientID     string
	SessionID       string
	Challenge       string
	ChallengeMethod string
	State           string
	RedirectURI     string
}

func (s *Services) OAuthDynamicRegistrationIAT2FARender(
	ctx context.Context,
	opts OAuthDynamicRegistrationIAT2FARenderOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationLocation, "OAuthDynamicRegistrationIAT2FARender").With(
		"clientId", opts.ACCClientID,
	)
	logger.InfoContext(ctx, "Handling OAuth dynamic registration IAT 2FA...")

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationIAT2FA(ctx, cache.GetAccountCredentialsDynamicRegistrationIAT2FAOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT 2FA", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.WarnContext(ctx, "Failed to get account credentials dynamic registration IAT 2FA")
		return "", exceptions.NewUnauthorizedError()
	}

	if opts.ACCClientID != data.ClientID {
		logger.WarnContext(ctx, "Client IDs do not match", "sessionClientId", data.ClientID)
		return "", exceptions.NewUnauthorizedError()
	}
	if data.Domain != opts.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", data.Domain)
		return "", exceptions.NewUnauthorizedError()
	}
	if data.State != opts.State {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", exceptions.NewUnauthorizedError()
	}
	if data.RedirectURI != opts.RedirectURI {
		logger.WarnContext(ctx, "OAuth Redirect URI does not match")
		return "", exceptions.NewUnauthorizedError()
	}

	csrfToken, err := s.cache.SaveAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
		ctx,
		cache.SaveAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions{
			RequestID: opts.RequestID,
			SessionID: opts.SessionID,
			TwoFATTL:  s.jwt.Get2FATTL(),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT 2FA CSRF token", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	twoFAhtml, err := templates.BuildAccountDynamicRegistrationIAT2FATemplate(
		templates.AccountDynamicRegistrationIAT2FAOptions{
			ACCClientID:         opts.ACCClientID,
			Domain:              opts.Domain,
			SessionID:           opts.SessionID,
			CSRFToken:           csrfToken,
			State:               data.State,
			CodeChallenge:       opts.Challenge,
			CodeChallengeMethod: opts.ChallengeMethod,
			RedirectURI:         data.RedirectURI,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build account dynamic registration IAT 2FA template", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return twoFAhtml, nil
}

type OAuthDynamicRegistrationIAT2FAReRenderOptions struct {
	RequestID       string
	Domain          string
	ACCClientID     string
	SessionID       string
	Errors          []string
	CSRFToken       string
	Challenge       string
	ChallengeMethod string
	State           string
	RedirectURI     string
}

func (s *Services) OAuthDynamicRegistrationIAT2FAReRender(
	ctx context.Context,
	opts OAuthDynamicRegistrationIAT2FAReRenderOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationLocation, "OAuthDynamicRegistrationIAT2FAReRender").With(
		"clientId", opts.ACCClientID,
	)
	logger.InfoContext(ctx, "Re-rendering OAuth dynamic registration IAT 2FA...")

	twoFAhtml, err := templates.BuildAccountDynamicRegistrationIAT2FATemplate(
		templates.AccountDynamicRegistrationIAT2FAOptions{
			Errors:              opts.Errors,
			ACCClientID:         opts.ACCClientID,
			Domain:              opts.Domain,
			SessionID:           opts.SessionID,
			CSRFToken:           opts.CSRFToken,
			State:               opts.State,
			CodeChallenge:       opts.Challenge,
			CodeChallengeMethod: opts.ChallengeMethod,
			RedirectURI:         opts.RedirectURI,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build account dynamic registration IAT 2FA template", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	return twoFAhtml, nil
}

func map2FATypeTokens(twoFAType string) (tokens.TwoFAType, *exceptions.ServiceError) {
	switch twoFAType {
	case TwoFactorTypeEmail:
		return tokens.TwoFATypeEmail, nil
	case TwoFactorTypeTotp:
		return tokens.TwoFATypeTOTP, nil
	default:
		return "", exceptions.NewValidationError("invalid two factor type")
	}
}

type OAuthDynamicRegistrationIATVerify2FACodeOptions struct {
	RequestID     string
	ACCClientID   string
	Domain        string
	SessionID     string
	CSRFToken     string
	Code          string
	BackendDomain string
}

func (s *Services) OAuthDynamicRegistrationIATVerify2FACode(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATVerify2FACodeOptions,
) (string, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationLocation, "OAuthDynamicRegistrationIATVerify2FACode").With(
		"clientId", opts.ACCClientID,
		"sessionId", opts.SessionID,
	)
	logger.InfoContext(ctx, "Verifying OAuth dynamic registration IAT 2FA...")

	verifiedCSRF, err := s.cache.VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
		ctx,
		cache.VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions{
			RequestID: opts.RequestID,
			SessionID: opts.SessionID,
			CSRFToken: opts.CSRFToken,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account credentials dynamic registration IAT 2FA CSRF token", "error", err)
		return "", "", exceptions.NewInternalServerError()
	}
	if !verifiedCSRF {
		logger.WarnContext(ctx, "Invalid CSRF token")
		return "", "", exceptions.NewForbiddenError()
	}

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationIAT2FA(ctx, cache.GetAccountCredentialsDynamicRegistrationIAT2FAOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT 2FA", "error", err)
		return "", "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.WarnContext(ctx, "Failed to get account credentials dynamic registration IAT 2FA")
		return "", "", exceptions.NewUnauthorizedError()
	}
	if opts.ACCClientID != data.ClientID {
		logger.WarnContext(ctx, "Client IDs do not match", "sessionClientId", data.ClientID)
		return "", "", exceptions.NewUnauthorizedError()
	}
	twoFAType, serviceErr := map2FATypeTokens(data.TwoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return "", "", serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountPublicID,
		Version:   data.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
		return "", "", serviceErr
	}
	if serviceErr := s.verifyAccount2FAInternal(ctx, verifyAccount2FAInternalOptions{
		requestID:       opts.RequestID,
		accountID:       accountDTO.ID(),
		accountPublicID: accountDTO.PublicID,
		accountVersion:  accountDTO.Version(),
		twoFAType:       twoFAType,
		code:            opts.Code,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to verify account two factor", "serviceError", serviceErr)
		return "", "", serviceErr
	}

	if _, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		Domain:          data.Domain,
	}); serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
			return "", "", serviceErr
		}

		if err := s.cache.DeleteAccountCredentialsDynamicRegistrationIATAuth(
			ctx,
			cache.DeleteAccountCredentialsDynamicRegistrationIATAuthOptions{
				RequestID: opts.RequestID,
				ClientID:  opts.ACCClientID,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account credentials dynamic registration IAT auth", "error", err)
			return "", "", exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Account credentials registration domain not found")
		return "", "", exceptions.NewForbiddenError()
	}

	sessionKey, err := s.cache.CreateAccountCredentialsRegistrationSessionKey(
		ctx,
		cache.CreateAccountCredentialsRegistrationSessionKeyOptions{
			RequestID:       opts.RequestID,
			ClientID:        opts.ACCClientID,
			Domain:          opts.Domain,
			AccountPublicID: accountDTO.PublicID,
			AccountVersion:  accountDTO.Version(),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account credentials registration session", "error", err)
		return "", "", exceptions.NewInternalServerError()
	}

	return oauthDynamicRegistrationIATAuthPath, sessionKey, nil
}

// TODO: add external callbacks

type VerifyOAuthDynamicRegistrationIATCodeOptions struct {
	RequestID    string
	Code         string
	CodeVerifier string
	Domain       string
}

func (s *Services) VerifyOAuthDynamicRegistrationIATCode(
	ctx context.Context,
	opts VerifyOAuthDynamicRegistrationIATCodeOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationIATLocation, "VerifyOAuthDynamicRegistrationIATCode")
	logger.InfoContext(ctx, "Verifying account credentials registration IAT code...")

	data, found, err := s.cache.VerifyAccountCredentialsRegistrationIATCode(ctx, cache.VerifyAccountCredentialsRegistrationIATCodeOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account credentials registration IAT code", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if !found {
		logger.DebugContext(ctx, "Account credentials registration IAT code not found or invalid")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if data.Domain != opts.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", data.Domain)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	ok, err := utils.CompareShaBase64(data.Challenge, opts.CodeVerifier)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare challenge", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth Code challenge verification failed")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountPublicID,
		Version:   data.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	tldOneDomain, err := publicsuffix.EffectiveTLDPlusOne(opts.Domain)
	if err != nil {
		logger.WarnContext(ctx, "Invalid domain", "error", err)
		return dtos.AuthDTO{}, exceptions.NewValidationError("invalid client_id")
	}

	var count int64
	if tldOneDomain != data.Domain {
		count, err = s.database.CountVerifiedDynamicRegistrationDomainsByDomainsAndAccountPublicID(
			ctx,
			database.CountVerifiedDynamicRegistrationDomainsByDomainsAndAccountPublicIDParams{
				AccountPublicID: accountDTO.PublicID,
				Domains:         []string{data.Domain, tldOneDomain},
			},
		)
	} else {
		count, err = s.database.CountVerifiedDynamicRegistrationDomainsByDomainAndAccountPublicID(
			ctx,
			database.CountVerifiedDynamicRegistrationDomainsByDomainAndAccountPublicIDParams{
				AccountPublicID: accountDTO.PublicID,
				Domain:          data.Domain,
			},
		)
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count verified account dynamic registration domains by domains and account public ID", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if count == 0 {
		logger.WarnContext(ctx, "Account does not have any verified dynamic registration domains matching the OAuth Domain")
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}

	tokenTTL := s.jwt.GetDynamicRegistrationTTL()
	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.DynamicRegistrationIAT(tokens.DynamicRegistrationIATOptions{
			AccountPublicID: accountDTO.PublicID,
			AccountVersion:  accountDTO.Version(),
			Domain:          data.Domain,
			ClientID:        data.ClientID,
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeDynamicRegistration,
			TTL:       tokenTTL,
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.RequestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.RequestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.RequestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign account credentials registration IAT", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Verified account credentials registration IAT code successfully")
	return dtos.NewAuthDTO(signedToken, tokenTTL), nil
}

type OAuthDynamicRegistrationIATExtGetOptions struct {
	RequestID     string
	ACCClientID   string
	Domain        string
	Provider      string
	CallbackURL   string
	RedirectURI   string
	State         string
	BackendDomain string
}

func (s *Services) OAuthDynamicRegistrationIATExtGet(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATExtGetOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "OAuthDynamicRegistrationIATExtGet").With(
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "External logging in account...")

	authUrlOpts := oauth.AuthorizationURLOptions{
		RequestID:   opts.RequestID,
		Scopes:      make([]oauth.Scope, 0),
		RedirectURL: opts.CallbackURL,
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
		return "", exceptions.NewInternalServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get authorization url or State", "error", serviceErr)
		return "", serviceErr
	}

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(ctx, cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ACCClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", exceptions.NewNotFoundError()
	}

	if data.Domain != opts.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", data.Domain)
		return "", exceptions.NewUnauthorizedError()
	}
	if data.State != opts.State {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", exceptions.NewUnauthorizedError()
	}
	if data.RedirectURI != opts.RedirectURI {
		logger.WarnContext(ctx, "OAuth Redirect URI does not match")
		return "", exceptions.NewUnauthorizedError()
	}

	if err := s.cache.SaveAccountCredentialsDynamicRegistrationIATExtAuth(ctx, cache.SaveAccountCredentialsDynamicRegistrationIATExtAuthOptions{
		RequestID:    opts.RequestID,
		ClientID:     opts.ACCClientID,
		Domain:       opts.Domain,
		Provider:     opts.Provider,
		State:        state,
		RequestState: opts.State,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT external auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "Saved account credentials dynamic registration IAT external auth successfully")
	return oauthUrl, nil
}

type OAuthDynamicRegistrationIATExtCBOptions struct {
	RequestID     string
	ACCClientID   string
	Provider      string
	State         string
	Code          string
	RedirectURL   string
	BackendDomain string
}

func (s *Services) OAuthDynamicRegistrationIATExtCB(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATExtCBOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "OAuthDynamicRegistrationIATExtCB")
	logger.InfoContext(ctx, "External callback for account...")

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationIATExtAuth(ctx, cache.GetAccountCredentialsDynamicRegistrationIATExtAuthOptions{
		RequestID: opts.RequestID,
		Provider:  opts.Provider,
		State:     opts.State,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT external auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT external auth not found")
		return "", exceptions.NewNotFoundError()
	}

	if data.ClientID != opts.ACCClientID {
		logger.WarnContext(ctx, "Client IDs do not match", "dataClientId", data.ClientID)
		return "", exceptions.NewUnauthorizedError()
	}

	accessTokenOpts := oauth.AccessTokenOptions{
		RequestID:   opts.RequestID,
		Code:        opts.Code,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var token string
	var serviceErr *exceptions.ServiceError
	switch opts.Provider {
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
		return "", exceptions.NewInternalServerError()
	}
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get oauth access token", "error", serviceErr)
		return "", serviceErr
	}

	authData, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(ctx, cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ACCClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", exceptions.NewNotFoundError()
	}

	if authData.Domain != data.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", authData.Domain)
		return "", exceptions.NewUnauthorizedError()
	}
	if authData.State != data.RequestState {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", exceptions.NewUnauthorizedError()
	}

	userData, serviceErr := s.extOAuthUser(ctx, logger, extOAuthUserOptions{
		requestID: opts.RequestID,
		provider:  opts.Provider,
		token:     token,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.RequestID,
		Email:     userData.Email,
	})
	if serviceErr != nil {
		return "", serviceErr
	}
	if _, serviceErr := s.GetAccountAuthProvider(ctx, GetAccountAuthProviderOptions{
		RequestID: opts.RequestID,
		PublicID:  accountDTO.PublicID,
		Provider:  opts.Provider,
	}); serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account auth provider", "serviceError", serviceErr)
			return "", serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "serviceError", serviceErr)
		return "", exceptions.NewUnauthorizedError()
	}

	cbURL, serviceErr := s.generateOAuthDynamicRegistrationIATCallback(
		ctx,
		generateOAuthDynamicRegistrationIATCallbackOptions{
			requestID:       opts.RequestID,
			clientID:        opts.ACCClientID,
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			challenge:       authData.Challenge,
			domain:          authData.Domain,
			redirectURI:     authData.RedirectURI,
			state:           authData.State,
			backendDomain:   opts.BackendDomain,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth dynamic registration IAT callback", "serviceError", serviceErr)
		return "", serviceErr
	}

	return cbURL, nil
}

type OAuthDynamicRegistrationIATExtAppleCBOptions struct {
	RequestID     string
	ACCClientID   string
	Email         string
	Code          string
	State         string
	RedirectURL   string
	BackendDomain string
}

func (s *Services) OAuthDynamicRegistrationIATExtAppleCB(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATExtAppleCBOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "OAuthDynamicRegistrationIATExtAppleCB")
	logger.InfoContext(ctx, "External callback for account...")

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationIATExtAuth(ctx, cache.GetAccountCredentialsDynamicRegistrationIATExtAuthOptions{
		RequestID: opts.RequestID,
		Provider:  AuthProviderApple,
		State:     opts.State,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT external auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT external auth not found")
		return "", exceptions.NewNotFoundError()
	}

	if data.ClientID != opts.ACCClientID {
		logger.WarnContext(ctx, "Client IDs do not match", "dataClientId", data.ClientID)
		return "", exceptions.NewUnauthorizedError()
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

	authData, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(ctx, cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ACCClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", exceptions.NewNotFoundError()
	}

	if authData.Domain != data.Domain {
		logger.WarnContext(ctx, "OAuth Domain does not match", "dataDomain", authData.Domain)
		return "", exceptions.NewUnauthorizedError()
	}
	if authData.State != data.RequestState {
		logger.WarnContext(ctx, "OAuth State does not match")
		return "", exceptions.NewUnauthorizedError()
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

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.RequestID,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		return "", serviceErr
	}
	if _, serviceErr := s.GetAccountAuthProvider(ctx, GetAccountAuthProviderOptions{
		RequestID: opts.RequestID,
		PublicID:  accountDTO.PublicID,
		Provider:  AuthProviderApple,
	}); serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account auth provider", "serviceError", serviceErr)
			return "", serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "serviceError", serviceErr)
		return "", exceptions.NewUnauthorizedError()
	}

	cbURL, serviceErr := s.generateOAuthDynamicRegistrationIATCallback(
		ctx,
		generateOAuthDynamicRegistrationIATCallbackOptions{
			requestID:       opts.RequestID,
			clientID:        opts.ACCClientID,
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			challenge:       authData.Challenge,
			domain:          authData.Domain,
			redirectURI:     authData.RedirectURI,
			state:           authData.State,
			backendDomain:   opts.BackendDomain,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth dynamic registration IAT callback", "serviceError", serviceErr)
		return "", serviceErr
	}

	return cbURL, nil
}
