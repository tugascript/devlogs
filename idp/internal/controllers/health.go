// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import "github.com/gofiber/fiber/v2"

func (c *Controllers) HealthCheck(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, "health", "HealthCheck")
	logRequest(logger, ctx)

	if serviceErr := c.services.HealthCheck(ctx.UserContext(), requestID); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	return ctx.SendStatus(fiber.StatusOK)
}
