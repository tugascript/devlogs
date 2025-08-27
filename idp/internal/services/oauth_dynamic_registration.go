// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"net/url"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/templates"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const oauthDynamicRegistrationLocation string = "oauth_dynamic_registration"

type OAuthDynamicRegistrationIATAuthOptions struct {
	RequestID           string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	RedirectURI         string
}

func (s *Services) OAuthDynamicRegistrationIATAuth(
	ctx context.Context,
	opts OAuthDynamicRegistrationIATAuthOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		oauthDynamicRegistrationLocation,
		"OAuthDynamicRegistrationIATAuth",
	).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.InfoContext(ctx, "Starting OAuth dynamic registration IAT authorization...")

	hashedChallenge, serviceErr := hashChallenge(opts.CodeChallenge, opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Invalid code challenge", "serviceError", serviceErr)
		return "", serviceErr
	}

	clientID, csrfToken, err := s.cache.SaveAccountCredentialsDynamicRegistrationIATAuth(
		ctx,
		cache.SaveAccountCredentialsDynamicRegistrationIATAuthOptions{
			RequestID:   opts.RequestID,
			Challenge:   hashedChallenge,
			State:       opts.State,
			RedirectURI: opts.RedirectURI,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	loginHTML, err := templates.BuildAccountDynamicRegistrationIATAuthTemplate(
		templates.AccountDynamicRegistrationIATAuthOptions{
			ClientID:            clientID,
			CSRFToken:           csrfToken,
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

type createAccountCredentialsRegistrationIATCodeOptions struct {
	requestID       string
	clientID        string
	accountPublicID uuid.UUID
	accountVersion  int32
	challenge       string
	domain          string
}

func (s *Services) createAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts createAccountCredentialsRegistrationIATCodeOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsRegistrationIATLocation, "createAccountCredentialsRegistrationIATCode").With(
		"clientId", opts.clientID,
		"accountPublicId", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Creating account credentials registration IAT code...")

	count, err := s.database.CountAppsByClientIDAndAccountPublicID(
		ctx,
		database.CountAppsByClientIDAndAccountPublicIDParams{
			ClientID:        opts.clientID,
			AccountPublicID: opts.accountPublicID,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count apps by client ID and account public ID", "error", err)
		return "", exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "App with the same client ID already exists for this account")
		return "", exceptions.NewUnauthorizedError()
	}

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

	logger.InfoContext(ctx, "Created account credentials registration IAT code successfully")
	return code, nil
}

type OAuthDynamicRegistrationIATLoginOptions struct {
	RequestID           string
	ClientID            string
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
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationLocation, "OAuthDynamicRegistrationIATLogin").With(
		"clientId", opts.ClientID,
		"email", opts.Email,
	)
	logger.InfoContext(ctx, "Logging in with OAuth dynamic registration IAT...")

	data, found, err := s.cache.GetAccountCredentialsDynamicRegistrationAuthIAT(ctx, cache.GetAccountCredentialsDynamicRegistrationIATAuthOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.ErrorContext(ctx, "Account credentials dynamic registration IAT not found")
		return "", exceptions.NewNotFoundValidationError("invalid client ID")
	}

	hashedChallenge, err := hashChallenge(opts.CodeChallenge, opts.CodeChallengeMethod)
	if err != nil {
		logger.ErrorContext(ctx, "Invalid code challenge", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	// Note this is not the verifier so standard comparison is ok
	if hashedChallenge != data.Challenge {
		logger.WarnContext(ctx, "OAuth Code challenge verification failed")
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

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.RequestID,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return "", serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return "", exceptions.NewUnauthorizedError()
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
			return "", serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "error", err)
		return "", exceptions.NewUnauthorizedError()
	}

	passwordVerified, err := utils.Argon2CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !passwordVerified {
		logger.WarnContext(ctx, "Passwords do not match")
		return "", exceptions.NewUnauthorizedError()
	}
	if !accountDTO.EmailVerified() {
		logger.InfoContext(ctx, "Account is not confirmed")
		return "", exceptions.NewForbiddenError()
	}

	// TODO: add 2FA redirect here

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		Domain:          data.Domain,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
			return "", serviceErr
		}

		if err := s.cache.DeleteAccountCredentialsDynamicRegistrationIATAuth(
			ctx,
			cache.DeleteAccountCredentialsDynamicRegistrationIATAuthOptions{
				RequestID: opts.RequestID,
				ClientID:  opts.ClientID,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account credentials dynamic registration IAT auth", "error", err)
			return "", exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Account credentials registration domain not found")
		return "", exceptions.NewForbiddenError()
	}
	if !domainDTO.Verified {
		logger.ErrorContext(ctx, "Account credentials registration domain is not verified")
		return "", exceptions.NewForbiddenError()
	}

	code, serviceErr := s.createAccountCredentialsRegistrationIATCode(
		ctx,
		createAccountCredentialsRegistrationIATCodeOptions{
			requestID:       opts.RequestID,
			clientID:        opts.ClientID,
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			challenge:       data.Challenge,
			domain:          data.Domain,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create account credentials registration IAT code", "serviceError", serviceErr)
		return "", serviceErr
	}
	if err := s.cache.DeleteAccountCredentialsDynamicRegistrationIATAuth(
		ctx,
		cache.DeleteAccountCredentialsDynamicRegistrationIATAuthOptions{
			RequestID: opts.RequestID,
			ClientID:  opts.ClientID,
		},
	); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account credentials dynamic registration IAT auth", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	queryParams := make(url.Values)
	queryParams.Add("code", code)
	queryParams.Add("state", data.State)
	queryParams.Add("iss", "https://"+opts.BackendDomain)
	return data.RedirectURI + "?" + queryParams.Encode(), nil
}

type OAuthDynamicRegistrationIAT2FAOptions struct {
	RequestID string
	ClientID  string
	Code      string
}

type OAuthDynamicRegistrationOptions struct {
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	ResponseTypes           []string
	GrantTypes              []string
	ApplicationType         string
	ClientName              string
	ClientURI               string
	LogoURI                 string
	Scope                   string
	Contacts                []string
	TOSURI                  string
	PolicyURI               string
	JWKsURI                 string
	JWKs                    []string
	SoftwareID              string
	SoftwareVersion         string
}
