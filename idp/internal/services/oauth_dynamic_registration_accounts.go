// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"slices"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const oauthDynamicRegistrationAccountsLocation string = "oauth_dynamic_registration_accounts"

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
			hostUsername:    opts.hostUsername,
			requestID:       opts.requestID,
			challenge:       opts.challenge,
			challengeMethod: opts.challengeMethod,
			domain:          opts.domain,
			redirectURI:     opts.redirectURI,
			state:           opts.state,
		})
	}
	if !hostMatchesAccount(opts.hostUsername, accountDTO.Username) {
		logger.WarnContext(ctx, "Refresh token account does not match host")
		return s.oauthDynamicRegistrationIATAuth(ctx, oauthDynamicRegistrationIATAuthOptions{
			hostUsername:    opts.hostUsername,
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
			hostUsername:    opts.hostUsername,
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

type initiateOAuthDynamicRegistrationIATAuthAccountsOptions struct {
	requestID    string
	sessionKey   string
	refreshToken string
	domain       string
}

func (s *Services) initiateOAuthDynamicRegistrationIATAuthAccounts(
	ctx context.Context,
	opts initiateOAuthDynamicRegistrationIATAuthAccountsOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthDynamicRegistrationAccountsLocation, "CreateOAuthDynamicRegistrationAccount")
	logger.InfoContext(ctx, "Creating OAuth dynamic registration account...")

	if opts.sessionKey == "" {
		logger.DebugContext(ctx, "No session key provided")

		if opts.refreshToken != "" {
			logger.DebugContext(ctx, "Refresh token provided, verifying...")
		}
	}

	data, credsClientID, verified, found, err := s.cache.VerifyAccountCredentialsRegistrationSessionKey(
		ctx,
		cache.VerifyAccountCredentialsRegistrationSessionKeyOptions{
			RequestID:  opts.requestID,
			SessionKey: opts.sessionKey,
			Domain:     opts.domain,
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
			RequestID: opts.requestID,
			ClientID:  credsClientID,
		},
	); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account credentials registration session key", "error", err)
		return "", exceptions.NewInternalServerError()
	}
}
