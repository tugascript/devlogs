// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthLocation string = "oauth"

	grantTypeRefresh           string = "refresh_token"
	grantTypeAuthorization     string = "authorization_code"
	grantTypeClientCredentials string = "client_credentials"
)

func formatAccountRedirectURL(backendDomain, provider string) string {
	return fmt.Sprintf("https://%s/v1/auth/oauth2/%s/callback", backendDomain, provider)
}

func (c *Controllers) AccountOAuthURL(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountOAuthURL")
	logRequest(logger, ctx)

	urlParams := params.OAuthURLParams{Provider: ctx.Params("provider")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	url, serviceErr := c.services.AccountOAuthURL(ctx.UserContext(), services.AccountOAuthURLOptions{
		RequestID:   requestID,
		Provider:    urlParams.Provider,
		RedirectURL: formatAccountRedirectURL(c.backendDomain, urlParams.Provider),
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(url, fiber.StatusFound)
}

func (c *Controllers) acceptCallback(logger *slog.Logger, ctx *fiber.Ctx, oauthParams string) error {
	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(
		fmt.Sprintf("https://%s/auth/callback?%s", c.frontendDomain, oauthParams),
		fiber.StatusFound,
	)
}

func (c *Controllers) errorCallback(logger *slog.Logger, ctx *fiber.Ctx, errStr string) error {
	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(
		fmt.Sprintf("https://%s/auth/callback?error=%s", c.frontendDomain, errStr),
		fiber.StatusFound,
	)
}

func (c *Controllers) AccountOAuthCallback(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountOAuthCallback")
	logRequest(logger, ctx)

	urlParams := params.OAuthURLParams{Provider: ctx.Params("provider")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	queryParams := params.OAuthCallbackQueryParams{
		Code:  ctx.Query("code"),
		State: ctx.Query("state"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), queryParams); err != nil {
		errQuery := ctx.Query("error")
		if errQuery != "" {
			return c.errorCallback(logger, ctx, errQuery)
		}

		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	oauthParams, serviceErr := c.services.ExtLoginAccount(ctx.UserContext(), services.ExtLoginAccountOptions{
		RequestID:   requestID,
		Provider:    urlParams.Provider,
		Code:        queryParams.Code,
		State:       queryParams.State,
		RedirectURL: formatAccountRedirectURL(c.backendDomain, urlParams.Provider),
	})
	if serviceErr != nil {
		switch serviceErr.Code {
		case exceptions.CodeUnauthorized, exceptions.CodeForbidden:
			return c.errorCallback(logger, ctx, exceptions.OAuthErrorAccessDenied)
		case exceptions.CodeNotFound, exceptions.CodeValidation:
			return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
		default:
			return c.errorCallback(logger, ctx, exceptions.OAuthServerError)
		}
	}

	return c.acceptCallback(logger, ctx, oauthParams)
}

func (c *Controllers) AccountAppleCallback(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountAppleCallback")
	logRequest(logger, ctx)

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	body := new(bodies.AppleLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	user := new(bodies.AppleUser)
	if err := json.Unmarshal([]byte(body.User), user); err != nil {
		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), user); err != nil {
		logger.WarnContext(ctx.UserContext(), "Failed to parse apple user data")
		return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}

	oauthParams, serviceErr := c.services.AppleLoginAccount(ctx.UserContext(), services.AppleLoginAccountOptions{
		RequestID: requestID,
		FirstName: user.Name.FirstName,
		LastName:  user.Name.LastName,
		Email:     user.Email,
		Code:      body.Code,
		State:     body.State,
	})
	if serviceErr != nil {
		switch serviceErr.Code {
		case exceptions.CodeUnauthorized, exceptions.CodeForbidden:
			return c.errorCallback(logger, ctx, exceptions.OAuthErrorAccessDenied)
		case exceptions.CodeNotFound, exceptions.CodeValidation:
			return c.errorCallback(logger, ctx, exceptions.OAuthErrorInvalidRequest)
		default:
			return c.errorCallback(logger, ctx, exceptions.OAuthServerError)
		}
	}

	return c.acceptCallback(logger, ctx, oauthParams)
}

func (c *Controllers) processAccountOAuthHeader(ctx *fiber.Ctx) *exceptions.ServiceError {
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return exceptions.NewUnauthorizedError()
	}

	accountClaims, scopes, serviceErr := c.services.ProcessOAuthHeader(authHeader)
	if serviceErr != nil {
		return serviceErr
	}
	if !slices.Contains(scopes, tokens.AccountScopeOAuth) {
		return exceptions.NewUnauthorizedError()
	}

	ctx.Locals("account", accountClaims)
	return nil
}

func oauthErrorResponseMapper(logger *slog.Logger, ctx *fiber.Ctx, serviceErr *exceptions.ServiceError) error {
	switch serviceErr.Code {
	case exceptions.CodeUnauthorized:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	case exceptions.CodeValidation:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidGrant)
	default:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthServerError)
	}
}

func (c *Controllers) accountAuthorizationCodeToken(ctx *fiber.Ctx, requestID string) error {
	logger := c.buildLogger(requestID, oauthLocation, "accountAuthorizationCodeToken")

	if serviceErr := c.processAccountOAuthHeader(ctx); serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	}

	account, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	}

	body := bodies.AuthCodeLoginBody{
		GrantType:   ctx.FormValue("grant_type"),
		RedirectURI: ctx.FormValue("redirect_uri"),
		Code:        ctx.FormValue("code"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}
	if body.RedirectURI != fmt.Sprintf("https://%s/auth/callback", c.frontendDomain) {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	authDTO, serviceErr := c.services.OAuthLoginAccount(ctx.UserContext(), services.OAuthLoginAccountOptions{
		RequestID: requestID,
		ID:        int32(account.ID),
		Version:   account.Version,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func parseAHClientCredentials(ctx *fiber.Ctx) (string, string, *exceptions.ServiceError) {
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return "", "", exceptions.NewUnauthorizedError()
	}

	authHeaderSlice := strings.Split(authHeader, " ")
	if len(authHeaderSlice) != 2 || utils.Lowered(authHeaderSlice[0]) != "basic" {
		return "", "", exceptions.NewUnauthorizedError()
	}

	decoded, err := base64.StdEncoding.DecodeString(authHeaderSlice[1])
	if err != nil {
		return "", "", exceptions.NewUnauthorizedError()
	}

	decodedSlice := strings.Split(string(decoded), ":")
	if len(authHeaderSlice) != 2 {
		return "", "", exceptions.NewUnauthorizedError()
	}

	return decodedSlice[0], decodedSlice[1], nil
}

var accountClientCredentialsScopes = map[tokens.AccountScope]bool{
	tokens.AccountScopeUsersWrite: true,
	tokens.AccountScopeUsersRead:  true,
	tokens.AccountScopeAppsWrite:  true,
	tokens.AccountScopeAppsRead:   true,
	tokens.AccountScopeAdmin:      true,
}

func processAccountClientCredentialScopes(scopes string) ([]tokens.AccountScope, bool) {
	if scopes == "" {
		return nil, true
	}

	scopesSlice := strings.Split(scopes, " ")
	if len(scopesSlice) == 0 {
		return nil, false
	}

	accountScopes := make([]tokens.AccountScope, len(scopesSlice))
	for i, scope := range scopesSlice {
		if !accountClientCredentialsScopes[scope] {
			return nil, false
		}

		accountScopes[i] = scope
	}

	return accountScopes, true
}

func (c *Controllers) accountClientCredentialsToken(ctx *fiber.Ctx, requestID string) error {
	logger := c.buildLogger(requestID, oauthLocation, "accountClientCredentialsToken")

	clientID, clientSecret, serviceErr := parseAHClientCredentials(ctx)
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	}

	body := bodies.ClientCredentialsBody{
		GrantType: ctx.FormValue("grant_type"),
		Audience:  ctx.FormValue("audience"),
		Scope:     ctx.FormValue("scope"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	scopes, ok := processAccountClientCredentialScopes(body.Scope)
	if !ok {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}

	authDTO, serviceErr := c.services.ClientCredentialsLoginAccount(
		ctx.UserContext(),
		services.ClientCredentialsLoginAccountOptions{
			RequestID:    requestID,
			Audience:     body.Audience,
			Scopes:       scopes,
			ClientID:     clientID,
			ClientSecret: clientSecret,
		},
	)
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) accountRefreshToken(ctx *fiber.Ctx, requestID string) error {
	logger := c.buildLogger(requestID, oauthLocation, "accountRefreshToken")

	body := bodies.GrantRefreshTokenBody{
		GrantType:    ctx.FormValue("grant_type"),
		RefreshToken: ctx.FormValue("refresh_token"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	authDTO, serviceErr := c.services.RefreshTokenAccount(ctx.UserContext(), services.RefreshTokenAccountOptions{
		RequestID:    requestID,
		RefreshToken: body.RefreshToken,
	})
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) AccountOAuthToken(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountOAuthToken")
	logRequest(logger, ctx)

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnsupportedMediaTypeError(
			"Content-Type must be application/x-www-form-urlencoded",
		))
	}

	grantType := ctx.FormValue("grant_type")
	if grantType == "" {
		logger.WarnContext(ctx.UserContext(), "Missing grant_type")
		logResponse(logger, ctx, fiber.StatusBadRequest)

	}

	switch grantType {
	case grantTypeRefresh:
		return c.accountRefreshToken(ctx, requestID)
	case grantTypeAuthorization:
		return c.accountAuthorizationCodeToken(ctx, requestID)
	case grantTypeClientCredentials:
		return c.accountClientCredentialsToken(ctx, requestID)
	default:
		logger.WarnContext(ctx.UserContext(), "Unsupported grant_type", "grantType", grantType)
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnsupportedGrantType)
	}
}

func (c *Controllers) AccountOAuthPublicJWKs(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountOAuthPublicJWKs")
	logRequest(logger, ctx)

	jwksDTO := c.services.GetAccountPublicJWKs(ctx.UserContext(), requestID)

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&jwksDTO)
}
