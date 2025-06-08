// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	wellKnownLocation         string = "well_known"
	wellKnownJWKsCacheControl string = "public, max-age=300, must-revalidate"
	wellKnownOIDCCacheControl string = "public, max-age=3600, must-revalidate"
)

func (c *Controllers) WellKnownJWKs(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, wellKnownLocation, "WellKnownJWKs")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	jwksDTO, etag, serviceErr := c.services.WellKnownJWKsWithCache(ctx.UserContext(), services.WellKnownJWKsOptions{
		RequestID:       requestID,
		AccountID:       accountID,
		AccountUsername: accountUsername,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if match := ctx.Get(fiber.HeaderIfNoneMatch); match == etag {
		logResponse(logger, ctx, fiber.StatusNotModified)
		return ctx.SendStatus(fiber.StatusNotModified)
	}

	ctx.Set(fiber.HeaderCacheControl, wellKnownJWKsCacheControl)
	ctx.Set(fiber.HeaderETag, etag)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&jwksDTO)
}

func (c *Controllers) WellKnownOIDCConfiguration(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, wellKnownLocation, "WellKnownOIDCConfiguration")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	configDTO, etag, serviceErr := c.services.WellKnownOIDCConfigurationWithCache(ctx.UserContext(), services.WellKnownOIDCConfigurationWithCacheOptions{
		RequestID:       requestID,
		AccountID:       accountID,
		BackendDomain:   c.backendDomain,
		AccountUsername: accountUsername,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if match := ctx.Get(fiber.HeaderIfNoneMatch); match == etag {
		logResponse(logger, ctx, fiber.StatusNotModified)
		return ctx.SendStatus(fiber.StatusNotModified)
	}

	ctx.Set(fiber.HeaderCacheControl, wellKnownOIDCCacheControl)
	ctx.Set(fiber.HeaderETag, etag)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&configDTO)
}
