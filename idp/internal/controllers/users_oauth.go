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

const usersOAuthLocation string = "users_oauth"

func (c *Controllers) AccountDistributedOAuthPublicJWKs(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersOAuthLocation, "AccountDistributedOAuthPublicJWKs")
	logRequest(logger, ctx)

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	etag, jwksDTO, serviceErr := c.services.GetAndCacheAccountDistributedJWK(
		ctx.UserContext(),
		services.GetAndCacheAccountDistributedJWKOptions{
			RequestID: requestID,
			AccountID: accountID,
		},
	)
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
