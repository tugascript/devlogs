// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"errors"
	"log/slog"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const middlewareLocation string = "middleware"

func processClaimsMiddleware(
	logger *slog.Logger,
	ctx *fiber.Ctx,
	processAH func(string) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError),
) error {
	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	accountClaims, scopes, serviceErr := processAH(authHeader)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("account", accountClaims)
	ctx.Locals("scopes", scopes)
	return ctx.Next()
}

func (c *Controllers) UserClaimsMiddleware(name services.AppKeyName) func(ctx *fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		requestID := getRequestID(ctx)
		logger := c.buildLogger(requestID, middlewareLocation, "ProcessUserClaimsMiddleware")

		authHeader := ctx.Get("Authorization")
		if authHeader == "" {
			return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
		}

		userClaims, appClaims, userScopes, serviceErr := c.services.ProcessUserAuthHeader(ctx.UserContext(), services.ProcessUserAuthHeaderOptions{
			RequestID:  requestID,
			AuthHeader: authHeader,
			Name:       name,
		})
		if serviceErr != nil {
			return serviceErrorResponse(logger, ctx, serviceErr)
		}

		ctx.Locals("user", userClaims)
		ctx.Locals("app", appClaims)
		ctx.Locals("user_scopes", userScopes)
		return ctx.Next()
	}
}

func (c *Controllers) AccountAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AccountAccessClaimsMiddleware")
	return processClaimsMiddleware(logger, ctx, c.services.ProcessAccountAuthHeader)
}

func (c *Controllers) TwoFAAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "TwoFAAccessClaimsMiddleware")
	return processClaimsMiddleware(logger, ctx, c.services.Process2FAAuthHeader)
}

func (c *Controllers) AppAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AppAccessClaimsMiddleware")

	authHeader := ctx.Get("Authorization")
	if authHeader == "" {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	appID, appClientID, serviceErr := c.services.ProcessAppAuthHeader(authHeader)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Locals("appID", appID)
	ctx.Locals("appClientID", appClientID)
	return ctx.Next()
}

func (c *Controllers) ScopeMiddleware(scope tokens.AccountScope) func(*fiber.Ctx) error {
	return func(ctx *fiber.Ctx) error {
		logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "ScopeMiddleware")

		scopes, serviceErr := getScopes(ctx)
		if serviceErr != nil {
			return serviceErrorResponse(logger, ctx, serviceErr)
		}

		for _, s := range scopes {
			if s == scope || s == tokens.AccountScopeAdmin {
				return ctx.Next()
			}
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

	if !slices.Contains(scopes, tokens.AccountScopeAdmin) {
		return serviceErrorResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	return ctx.Next()
}

func isValidSubdomain(sub string) bool {
	length := len(sub)
	if length < 1 || length > 63 {
		return false
	}

	return utils.IsValidSlug(sub)
}

func processHost(host string) (string, error) {
	hostArr := strings.Split(host, ".")
	if len(hostArr) < 2 {
		return "", errors.New("host must contain at least two parts")
	}

	username := hostArr[0]
	if !isValidSubdomain(username) {
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

	if !ok || account.ID == 0 {
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

func getAppClaims(ctx *fiber.Ctx) (int32, string, *exceptions.ServiceError) {
	appID, ok := ctx.Locals("appID").(int32)
	if !ok || appID == 0 {
		return 0, "", exceptions.NewUnauthorizedError()
	}

	appClientID, ok := ctx.Locals("appClientID").(string)
	if !ok || appClientID == "" {
		return 0, "", exceptions.NewUnauthorizedError()
	}

	return appID, appClientID, nil
}

func getUserClaims(ctx *fiber.Ctx) (tokens.UserClaims, tokens.AppClaims, []string, *exceptions.ServiceError) {
	user, ok := ctx.Locals("user").(tokens.UserClaims)
	if !ok || user.UserID == 0 {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	app, ok := ctx.Locals("app").(tokens.AppClaims)
	if !ok || app.AppID == 0 {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	scopes, ok := ctx.Locals("user_scopes").([]string)
	if !ok || scopes == nil {
		return tokens.UserClaims{}, tokens.AppClaims{}, nil, exceptions.NewForbiddenError()
	}

	return user, app, scopes, nil
}

func getHostAccount(ctx *fiber.Ctx) (string, int, *exceptions.ServiceError) {
	accountUsername, ok := ctx.Locals("accountUsername").(string)
	if !ok || accountUsername == "" {
		return "", 0, exceptions.NewNotFoundError()
	}

	accountID, ok := ctx.Locals("accountID").(int)
	if !ok || accountID == 0 {
		return "", 0, exceptions.NewNotFoundError()
	}

	return accountUsername, accountID, nil
}
