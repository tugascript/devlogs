// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oauth

import (
	"context"
	"encoding/json"

	"golang.org/x/oauth2"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const customLocation string = "custom"

type buildOAuthConfigOptions struct {
	clientID     string
	clientSecret string
	authURL      string
	tokenURL     string
	redirectURL  string
	scopes       []string
}

func buildOAuthConfig(opts buildOAuthConfigOptions) oauth2.Config {
	return oauth2.Config{
		ClientID:     opts.clientID,
		ClientSecret: opts.clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  opts.authURL,
			TokenURL: opts.tokenURL,
		},
		Scopes:      opts.scopes,
		RedirectURL: opts.redirectURL,
	}
}

type GetCustomAuthorizationURLOptions struct {
	RequestID    string
	RedirectURL  string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
}

func (p *Providers) GetCustomAuthorizationURL(
	ctx context.Context,
	opts GetCustomAuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  customLocation,
		Method:    "GetCustomAuthorizationURL",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting custom authorization URL...")

	state, err := utils.GenerateHexSecret(16)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating state", err)
		return "", "", exceptions.NewServerError()
	}

	cfg := buildOAuthConfig(buildOAuthConfigOptions{
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		authURL:      opts.AuthURL,
		tokenURL:     opts.TokenURL,
		redirectURL:  opts.RedirectURL,
		scopes:       opts.Scopes,
	})
	url := cfg.AuthCodeURL(state)
	logger.DebugContext(ctx, "Custom authorization URL generated successfully")
	return url, state, nil
}

type GetCustomAccessTokenOptions struct {
	RequestID    string
	RedirectURL  string
	ClientID     string
	ClientSecret string
	AuthURL      string
	TokenURL     string
	Scopes       []string
	Code         string
}

func (p *Providers) GetCustomAccessToken(
	ctx context.Context,
	opts GetCustomAccessTokenOptions,
) (string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  customLocation,
		Method:    "GetCustomAccessToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting custom access token...")

	cfg := buildOAuthConfig(buildOAuthConfigOptions{
		clientID:     opts.ClientID,
		clientSecret: opts.ClientSecret,
		authURL:      opts.AuthURL,
		tokenURL:     opts.TokenURL,
		redirectURL:  opts.RedirectURL,
		scopes:       opts.Scopes,
	})

	token, err := cfg.Exchange(ctx, opts.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to exchange the code for a token", "error", err)
		return "", exceptions.NewUnauthorizedError()
	}

	logger.DebugContext(ctx, "Access token exchanged successfully")
	return token.AccessToken, nil
}

type GetCustomUserDataOptions struct {
	RequestID   string
	Token       string
	UserDataURL string
	EmailKey    string
}

func (p *Providers) GetCustomUserData(
	ctx context.Context,
	opts GetCustomUserDataOptions,
) (string, map[string]any, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  customLocation,
		Method:    "GetCustomUserData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting custom user data...")

	body, status, err := getUserResponse(logger, ctx, opts.UserDataURL, opts.Token)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get user data", "error", err, "status", status)
		return "", nil, exceptions.NewUnauthorizedError()
	}

	logger.DebugContext(ctx, "Successfully retrieved user data")
	userData := make(map[string]any)
	if err = json.Unmarshal(body, &userData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal user data", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	if len(userData) == 0 {
		logger.DebugContext(ctx, "User data is empty")
		return "", nil, exceptions.NewUnauthorizedError()
	}

	email, ok := userData[opts.EmailKey].(string)
	if !ok || email == "" {
		logger.ErrorContext(ctx, "Failed to get email from user data")
		return "", nil, exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "User data retrieved successfully")
	return email, userData, nil
}
