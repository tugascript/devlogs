// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const middlewareLocation string = "middleware"

func (c *Controllers) UserAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, middlewareLocation, "UserAccessClaimsMiddleware")

	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userClaims, appClaims, userScopes, serviceErr := c.services.ProcessUserAuthHeader(
		ctx.UserContext(),
		services.ProcessUserAuthHeaderOptions{
			RequestID:  requestID,
			AuthHeader: authHeader,
			AccountID:  accountID,
			TokenType:  tokens.AuthTokenTypeAccess,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("user", userClaims)
	ctx.Locals("app", appClaims)
	ctx.Locals("userScopes", userScopes)
	return ctx.Next()
}

func (c *Controllers) User2FAClaimsMiddleware(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, middlewareLocation, "User2FAClaimsMiddleware")

	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userClaims, appClaims, serviceErr := c.services.ProcessUserPurposeHeader(
		ctx.UserContext(),
		services.ProcessUserPurposeHeaderOptions{
			RequestID:  requestID,
			AuthHeader: authHeader,
			AccountID:  accountID,
			TokenType:  tokens.PurposeTokenTypeTwoFA,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("user", userClaims)
	ctx.Locals("app", appClaims)
	return ctx.Next()
}

func (c *Controllers) AccountAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AccountAccessClaimsMiddleware")
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	accountClaims, scopes, serviceErr := c.services.ProcessAccountAuthHeader(
		ctx.UserContext(),
		services.ProcessAuthHeaderOptions{
			RequestID:  getRequestID(ctx),
			AuthHeader: authHeader,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("account", accountClaims)
	ctx.Locals("scopes", scopes)
	return ctx.Next()
}

func (c *Controllers) TwoFAAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "TwoFAAccessClaimsMiddleware")
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	accountClaims, serviceErr := c.services.Process2FAAuthHeader(
		ctx.UserContext(),
		services.ProcessAuthHeaderOptions{
			RequestID:  getRequestID(ctx),
			AuthHeader: authHeader,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("account", accountClaims)
	return ctx.Next()
}

func (c *Controllers) AppAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AppAccessClaimsMiddleware")

	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appClaims, serviceErr := c.services.ProcessAppAuthHeader(
		ctx.UserContext(),
		services.ProcessAppAuthHeaderOptions{
			RequestID:  getRequestID(ctx),
			AuthHeader: authHeader,
			AccountID:  accountID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("app", appClaims)
	return ctx.Next()
}

func (c *Controllers) ScopeMiddleware(scope tokens.AccountScope) func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "ScopeMiddleware")

		scopes, serviceErr := getScopes(ctx)
		if serviceErr != nil {
			return serviceErrorResponse(logger, ctx, serviceErr)
		}

		scopesHashset := utils.SliceToHashSet(scopes)
		if scopesHashset.Contains(scope) || scopesHashset.Contains(tokens.AccountScopeAdmin) {
			return ctx.Next()
		}

		return serviceErrorResponse(logger, ctx, exceptions.NewForbiddenError())
	}
}

func (c *Controllers) AdminScopeMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AdminScopeMiddleware")

	scopes, serviceErr := getScopes(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	scopesHashset := utils.SliceToHashSet(scopes)
	if !scopesHashset.Contains(tokens.AccountScopeAdmin) {
		return serviceErrorResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	return ctx.Next()
}

func processHost(host string) (string, error) {
	hostArr := strings.Split(host, ".")
	if len(hostArr) < 2 {
		return "", errors.New("host must contain at least two parts")
	}

	username := hostArr[0]
	if !utils.IsValidSubdomain(username) {
		return "", errors.New("invalid subdomain")
	}

	return username, nil
}

func (c *Controllers) AccountHostMiddleware(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, middlewareLocation, "AccountHostMiddleware")
	host := ctx.Get("Host")
	if host == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	username, err := processHost(host)
	if err != nil {
		logger.DebugContext(ctx.UserContext(), "invalid host", "error", err)
		return serviceErrorResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	accountID, serviceErr := c.services.GetAndCacheAccountIDByUsername(
		ctx.UserContext(),
		services.GetAccountIDByUsernameOptions{
			RequestID: requestID,
			Username:  username,
		},
	)
	if serviceErr != nil {
		logger.DebugContext(ctx.UserContext(), "failed to get account by username",
			"username", username,
			"error", serviceErr,
		)
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("accountUsername", username)
	ctx.Locals("accountID", accountID)
	return ctx.Next()
}

func getAccountClaims(ctx *fiber.Ctx) (tokens.AccountClaims, *exceptions.ServiceError) {
	account, ok := ctx.Locals("account").(tokens.AccountClaims)

	if !ok || account.AccountID == uuid.Nil {
		return tokens.AccountClaims{}, exceptions.NewUnauthorizedError()
	}

	return account, nil
}

func getScopes(ctx *fiber.Ctx) ([]tokens.AccountScope, *exceptions.ServiceError) {
	scopes, ok := ctx.Locals("scopes").([]tokens.AccountScope)
	if !ok || scopes == nil {
		return nil, exceptions.NewForbiddenError()
	}

	return scopes, nil
}

func getAppClaims(ctx *fiber.Ctx) (tokens.AppClaims, *exceptions.ServiceError) {
	app, ok := ctx.Locals("app").(tokens.AppClaims)
	if !ok || app.ClientID == "" {
		return tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}

	return app, nil
}

func getUserAccessClaims(ctx *fiber.Ctx) (tokens.UserAuthClaims, tokens.AppClaims, []database.Scopes, *exceptions.ServiceError) {
	user, ok := ctx.Locals("user").(tokens.UserAuthClaims)
	if !ok || user.UserID == uuid.Nil {
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	app, ok := ctx.Locals("app").(tokens.AppClaims)
	if !ok || app.ClientID == "" {
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	scopes, ok := ctx.Locals("user_scopes").([]database.Scopes)
	if !ok || scopes == nil {
		return tokens.UserAuthClaims{}, tokens.AppClaims{}, nil, exceptions.NewForbiddenError()
	}

	return user, app, scopes, nil
}

func getUserPurposeClaims(ctx *fiber.Ctx) (tokens.UserPurposeClaims, tokens.AppClaims, *exceptions.ServiceError) {
	user, ok := ctx.Locals("user").(tokens.UserPurposeClaims)
	if !ok || user.UserID == uuid.Nil {
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}

	app, ok := ctx.Locals("app").(tokens.AppClaims)
	if !ok || app.ClientID == "" {
		return tokens.UserPurposeClaims{}, tokens.AppClaims{}, exceptions.NewUnauthorizedError()
	}

	return user, app, nil
}

func getHostAccount(ctx *fiber.Ctx) (string, int32, *exceptions.ServiceError) {
	accountUsername, ok := ctx.Locals("accountUsername").(string)
	if !ok || accountUsername == "" {
		return "", 0, exceptions.NewNotFoundError()
	}

	accountID, ok := ctx.Locals("accountID").(int32)
	if !ok || accountID == 0 {
		return "", 0, exceptions.NewNotFoundError()
	}

	return accountUsername, accountID, nil
}
