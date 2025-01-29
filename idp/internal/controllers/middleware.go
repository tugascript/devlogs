package controllers

import (
	"log/slog"
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const middlewareLocation string = "middleware"

func (c *Controllers) processClaimsMiddleware(
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
	return c.processClaimsMiddleware(logger, ctx, c.services.ProcessAccountAuthHeader)
}

func (c *Controllers) TwoFAAccessClaimsMiddleware(ctx *fiber.Ctx) error {
	logger := c.buildLogger(getRequestID(ctx), middlewareLocation, "TwoFAAccessClaimsMiddleware")
	return c.processClaimsMiddleware(logger, ctx, c.services.Process2FAAuthHeader)
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

func (c *Controllers) AppIDMiddleware(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	userContext := ctx.UserContext()
	logger := c.buildLogger(requestID, "middleware", "AppIDMiddleware")
	logger.DebugContext(userContext, "Getting app AccountID...")

	hostname := ctx.Hostname()
	slug := hostname[:len(hostname)-len(c.backendDomain)-1]

	if slug == "" {
		logger.WarnContext(userContext, "Slug not found")
		return ctx.Next()
	}

	appID, err := c.services.GetAppIDBySlug(ctx.Context(), services.GetAppIDBySlugOptions{
		RequestID: requestID,
		Slug:      slug,
	})
	if err != nil {
		logger.ErrorContext(userContext, "Error getting app AccountID", "error", err)
		return ctx.Next()
	}

	logger.DebugContext(userContext, "App AccountID found", "appID", appID)
	ctx.Locals("appID", appID)
	return ctx.Next()
}
