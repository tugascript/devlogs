// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"log/slog"
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
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

func (c *Controllers) AccountAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "AccountAccessClaimsMiddleware")
	return processClaimsMiddleware(logger, ctx, c.services.ProcessAccountAuthHeader)
}

func (c *Controllers) TwoFAAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "TwoFAAccessClaimsMiddleware")
	return processClaimsMiddleware(logger, ctx, c.services.Process2FAAuthHeader)
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
