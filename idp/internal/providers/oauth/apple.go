// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"

	"github.com/tugascript/devlogs/idp/internal/exceptions"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	appleLocation string = "apple"

	appleKeysURL string = "https://appleid.apple.com/auth/keys"
)

var appleScopes = oauthScopes{
	email:   "email",
	profile: "name",
}

func NewAppleUserData(email, firstName, lastName string) UserData {
	name := fmt.Sprintf("%s %s", firstName, lastName)
	return UserData{
		Name:       name,
		FirstName:  firstName,
		LastName:   lastName,
		Username:   utils.Slugify(name),
		Email:      email,
		IsVerified: true,
	}
}

func (p *Providers) GetAppleAuthorizationURL(
	ctx context.Context,
	opts AuthorizationURLOptions,
) (string, string, *exceptions.ServiceError) {
	return getAuthorizationURL(ctx, getAuthorizationURLOptions{
		logger: utils.BuildLogger(p.logger, utils.LoggerOptions{
			Location:  appleLocation,
			Method:    "GetAppleAuthorizationURL",
			RequestID: opts.RequestID,
		}),
		cfg:         p.apple,
		redirectURL: opts.RedirectURL,
		oas:         appleScopes,
		scopes:      opts.Scopes,
	})
}

func (p *Providers) GetAppleIDToken(ctx context.Context, opts AccessTokenOptions) (string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  appleLocation,
		Method:    "GetAppleIDToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Apple AccountID token...")

	cfg := getConfig(p.apple, opts.RedirectURL, appleScopes, opts.Scopes)
	token, err := cfg.Exchange(ctx, opts.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to exchange the code for a token", "error", err)
		return "", exceptions.NewUnauthorizedError()
	}

	idToken := token.Extra("id_token")
	if idToken == nil {
		logger.ErrorContext(ctx, "AccountID token not present on exchange request")
		return "", exceptions.NewServerError()
	}

	idTokenStr, ok := idToken.(string)
	if !ok || idTokenStr == "" {
		logger.ErrorContext(ctx, "AccountID token is not a string")
		return "", exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "AccountID token exchanged successfully")
	return idTokenStr, nil
}

type AppleJWKsResponse struct {
	Keys []utils.RS256JWK `json:"keys"`
}

type AppleIDTokenClaims struct {
	Nonce          string      `json:"nonce"`
	NonceSupported bool        `json:"nonce_supported"`
	Email          string      `json:"email"`
	EmailVerified  interface{} `json:"email_verified"`
	IsPrivateEmail interface{} `json:"is_private_email"`
	RealUserStatus int         `json:"real_user_status"`
	TransferSub    string      `json:"transfer_sub"`
	jwt.RegisteredClaims
}

type ValidateAppleIDTokenOptions struct {
	RequestID string
	Token     string
	Email     string
}

func (p *Providers) ValidateAppleIDToken(
	ctx context.Context,
	opts ValidateAppleIDTokenOptions,
) (bool, *exceptions.ServiceError) {
	logger := utils.BuildLogger(p.logger, utils.LoggerOptions{
		Location:  appleLocation,
		Method:    "ValidateAppleIDToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Validating Apple AccountID token...")

	req, err := http.NewRequest(http.MethodGet, appleKeysURL, nil)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build Keys request", "error", err)
		return false, exceptions.NewServerError()
	}

	req.Header.Set("Accept", "application/json")

	logger.DebugContext(ctx, "Requesting Keys data...")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to request the token data", "error", err)
		return false, exceptions.NewServerError()
	}

	if res.StatusCode != http.StatusOK {
		logger.ErrorContext(ctx, "Responded with a non 200 OK status", "status", res.StatusCode)

		if res.StatusCode < 500 {
			return false, exceptions.NewUnauthorizedError()
		}

		return false, exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "Reading the body...")
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read the body", "error", err)
		return false, exceptions.NewServerError()
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.ErrorContext(ctx, "Failed to close response body", "error", err)
		}
	}()

	jwksRes := AppleJWKsResponse{}
	if err := json.Unmarshal(body, &jwksRes); err != nil {
		logger.ErrorContext(ctx, "Failed to parse Apple JWKs data", "error", err)
		return false, exceptions.NewServerError()
	}

	if len(jwksRes.Keys) == 0 {
		logger.ErrorContext(ctx, "No public JWKs found")
		return false, exceptions.NewServerError()
	}

	claims := AppleIDTokenClaims{}
	_, err = jwt.ParseWithClaims(opts.Token, &claims, func(token *jwt.Token) (interface{}, error) {
		if token == nil {
			return nil, errors.New("token is nil")
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, jwt.ErrInvalidKey
		}

		keyIdx := slices.IndexFunc(jwksRes.Keys, func(jwk utils.RS256JWK) bool {
			return jwk.Kid == kid
		})
		if keyIdx < 0 {
			logger.ErrorContext(ctx, "Key for AccountID token KID was not found")
			return nil, errors.New("key for AccountID token KID not found")
		}

		pubKey, err := utils.DecodeRS256Jwk(&jwksRes.Keys[keyIdx])
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decode public key", "error", err)
			return nil, err
		}

		return pubKey, nil
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify AccountID token", "error", err)
		return false, exceptions.NewServerError()
	}

	var emailVerified bool
	switch claims.EmailVerified.(type) {
	case string:
		emailVerified = utils.Lowered(claims.EmailVerified.(string)) == "true"
	case bool:
		emailVerified = claims.EmailVerified.(bool)
	}

	if claims.Email != opts.Email || !emailVerified {
		return false, nil
	}

	return true, nil
}
