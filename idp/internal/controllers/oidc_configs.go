// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	oidcConfigsLocation string = "oidc_configs"
)

func (c *Controllers) CreateOIDCConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oidcConfigsLocation, "CreateOIDCConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.OIDCConfigBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	jwtCryptoSuite, serviceErr := tokens.GetSupportedCryptoSuite(body.JwtCryptoSuite)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	oidcConfigDTO, serviceErr := c.services.CreateOIDCConfig(ctx.UserContext(), services.CreateOIDCConfigOptions{
		RequestID:      requestID,
		AccountID:      int32(accountClaims.ID),
		Claims:         body.Claims,
		Scopes:         body.Scopes,
		JwtCryptoSuite: jwtCryptoSuite,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&oidcConfigDTO)
}

func (c *Controllers) GetOIDCConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oidcConfigsLocation, "GetUserSchema")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	oidcConfigDTO, serviceErr := c.services.GetOrCreateOIDCConfig(
		ctx.UserContext(),
		services.GetOrCreateOIDCConfigOptions{
			RequestID: requestID,
			AccountID: int32(accountClaims.ID),
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&oidcConfigDTO)
}

func (c *Controllers) UpdateOIDCConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oidcConfigsLocation, "UpdateOIDCConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.OIDCConfigBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	oidcConfigDTO, serviceErr := c.services.UpdateOIDCConfig(ctx.UserContext(), services.UpdateOIDCConfigOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		Claims:    body.Claims,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&oidcConfigDTO)
}
