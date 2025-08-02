// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/utils"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	oauthLocation string = "oauth"

	publicJWKsCacheControl string = "public, max-age=300, must-revalidate"
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
	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(
		fmt.Sprintf("https://%s/auth/callback?%s", c.frontendDomain, oauthParams),
		fiber.StatusFound,
	)
}

func (c *Controllers) errorCallback(logger *slog.Logger, ctx *fiber.Ctx, errStr string) error {
	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
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

	accountClaims, serviceErr := c.services.ProcessOAuthHeader(
		ctx.UserContext(),
		services.ProcessAuthHeaderOptions{
			RequestID:  getRequestID(ctx),
			AuthHeader: authHeader,
		},
	)
	if serviceErr != nil {
		return serviceErr
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
	case exceptions.CodeForbidden:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnauthorizedClient)
	default:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthServerError)
	}
}

func oauthClientCredentialsErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, serviceErr *exceptions.ServiceError) error {
	switch serviceErr.Code {
	case exceptions.CodeUnauthorized:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	case exceptions.CodeValidation:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	case exceptions.CodeForbidden:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnauthorizedClient)
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
		PublicID:  account.AccountID,
		Version:   account.AccountVersion,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	if authDTO.RefreshToken != "" {
		c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	}

	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
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
	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) accountJWTBearer(ctx *fiber.Ctx, requestID string) error {
	logger := c.buildLogger(requestID, oauthLocation, "accountJWTBearer")

	body := bodies.JWTGrantBody{
		GrantType: ctx.FormValue("grant_type"),
		Scope:     ctx.FormValue("scope"),
		Assertion: ctx.FormValue("assertion"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	scopes, serviceErr := c.services.ProcessAccountCredentialsScope(
		ctx.UserContext(),
		services.ProcessAccountCredentialsScopeOptions{
			RequestID: requestID,
			Scope:     body.Scope,
		},
	)
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}

	authDTO, serviceErr := c.services.JWTBearerAccountLogin(ctx.UserContext(), services.JWTBearerAccountLoginOptions{
		RequestID:     requestID,
		Token:         body.Assertion,
		Scopes:        scopes,
		BackendDomain: c.backendDomain,
	})
	if serviceErr != nil {
		return oauthClientCredentialsErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) accountClientCredentials(ctx *fiber.Ctx, requestID string) error {
	logger := c.buildLogger(requestID, oauthLocation, "accountClientCredentials")

	body := bodies.ClientCredentialsBody{
		GrantType:    ctx.FormValue("grant_type"),
		Scope:        ctx.FormValue("scope"),
		Audience:     ctx.FormValue("audience"),
		ClientID:     ctx.FormValue("client_id"),
		ClientSecret: ctx.FormValue("client_secret"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}
	if body.Audience != "" &&
		utils.IsValidURL(body.Audience) &&
		utils.ProcessURL(body.Audience) != fmt.Sprintf("https://%s", c.backendDomain) {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorAccessDenied)
	}

	clientID, clientSecret, authMethod, serviceErr := c.services.ProcessClientCredentialsLoginData(
		ctx.UserContext(),
		services.ProcessClientCredentialsLoginDataOptions{
			RequestID:    requestID,
			ClientID:     body.ClientID,
			ClientSecret: body.ClientSecret,
			AuthHeader:   ctx.Get("Authorization"),
		},
	)
	if serviceErr != nil {
		return oauthClientCredentialsErrorResponse(logger, ctx, serviceErr)
	}

	scopes, serviceErr := c.services.ProcessAccountCredentialsScope(
		ctx.UserContext(),
		services.ProcessAccountCredentialsScopeOptions{
			RequestID: requestID,
			Scope:     body.Scope,
		},
	)
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}

	authDTO, serviceErr := c.services.ClientCredentialsAccountLogin(
		ctx.UserContext(),
		services.ClientCredentialsAccountLoginOptions{
			RequestID:    requestID,
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Scopes:       scopes,
			AuthMethod:   authMethod,
		},
	)
	if serviceErr != nil {
		return oauthClientCredentialsErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
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
	case grantTypeJwtBearer:
		return c.accountJWTBearer(ctx, requestID)
	case grantTypeClientCredentials:
		return c.accountClientCredentials(ctx, requestID)
	default:
		logger.WarnContext(ctx.UserContext(), "Unsupported grant_type", "grantType", grantType)
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnsupportedGrantType)
	}
}

func (c *Controllers) AccountOAuthPublicJWKs(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AccountOAuthPublicJWKs")
	logRequest(logger, ctx)

	etag, jwksDTO, serviceErr := c.services.GetAccountPublicJWKs(ctx.UserContext(), requestID)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if match := ctx.Get(fiber.HeaderIfNoneMatch); match == etag {
		logResponse(logger, ctx, fiber.StatusNotModified)
		return ctx.SendStatus(fiber.StatusNotModified)
	}

	ctx.Set(fiber.HeaderCacheControl, publicJWKsCacheControl)
	ctx.Set(fiber.HeaderETag, etag)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&jwksDTO)
}
