// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"log/slog"
	"net/url"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthDynamicRegistrationIATPath     string = paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken
	oauthDynamicRegistrationIATAuthPath string = oauthDynamicRegistrationIATPath + paths.OAuthAuth
)

type dynamicRegistrationRequest struct {
	domain      string
	state       string
	redirectURI string
}

func validateDynamicRegistrationRequest(saved, requested dynamicRegistrationRequest) *exceptions.ServiceError {
	if saved != requested {
		return exceptions.NewUnauthorizedError()
	}
	return nil
}

func dynamicRegistrationIssuerDomain(hostUsername, backendDomain string) string {
	if hostUsername == "" {
		return backendDomain
	}
	return hostUsername + "." + backendDomain
}

func oauthDynamicRegistrationIATExtCallbackURL(issuerDomain, accClientID, provider string) string {
	return "https://" + issuerDomain + oauthDynamicRegistrationIATPath + "/" + accClientID +
		paths.InitialAccessTokenAuthEXT + "/" + provider + paths.InitialAccessTokenCallback
}

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
	queryParams.Add("redirect_uri", opts.redirectURI)
	queryParams.Add("state", opts.state)
	queryParams.Add("code_challenge", opts.challenge)
	if opts.challengeMethod != "" {
		queryParams.Add("code_challenge_method", opts.challengeMethod)
	}
	return oauthDynamicRegistrationIATPath + "/" + opts.accClientID + paths.AuthLogin + "?" + queryParams.Encode()
}

type buildOAuthDynamicRegistrationIATCallbackURLOptions struct {
	redirectURI  string
	code         string
	state        string
	issuerDomain string
}

func buildOAuthDynamicRegistrationIATCallbackURL(opts buildOAuthDynamicRegistrationIATCallbackURLOptions) string {
	queryParams := make(url.Values)
	queryParams.Add("code", opts.code)
	queryParams.Add("state", opts.state)
	queryParams.Add("iss", "https://"+opts.issuerDomain)
	return opts.redirectURI + "?" + queryParams.Encode()
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

func (s *Services) authenticateDynamicRegistrationAccount(ctx context.Context, logger *slog.Logger, requestID, email, password string) (dtos.AccountDTO, *exceptions.ServiceError) {
	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: requestID,
		Email:     email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return dtos.AccountDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return dtos.AccountDTO{}, exceptions.NewUnauthorizedError()
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
			return dtos.AccountDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "error", err)
		return dtos.AccountDTO{}, exceptions.NewUnauthorizedError()
	}

	passwordVerified, err := utils.Argon2CompareHash(password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return dtos.AccountDTO{}, exceptions.NewInternalServerError()
	}
	if !passwordVerified {
		logger.WarnContext(ctx, "Passwords do not match")
		return dtos.AccountDTO{}, exceptions.NewUnauthorizedError()
	}
	if !accountDTO.EmailVerified() {
		logger.InfoContext(ctx, "Account is not confirmed")
		return dtos.AccountDTO{}, exceptions.NewForbiddenError()
	}

	return accountDTO, nil
}
