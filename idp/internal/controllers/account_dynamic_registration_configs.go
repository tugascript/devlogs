// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	accountDynamicRegistrationConfigsLocation string = "account_dynamic_registration_configs"
)

func (c *Controllers) UpsertAccountDynamicRegistrationConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(
		requestID,
		accountDynamicRegistrationConfigsLocation,
		"UpsertAccountDynamicRegistrationConfig",
	)
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AccountDynamicRegistrationConfigBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	dto, created, serviceErr := c.services.SaveAccountDynamicRegistrationConfig(
		ctx.UserContext(),
		services.SaveAccountDynamicRegistrationConfigOptions{
			RequestID:                                requestID,
			AccountPublicID:                          accountClaims.AccountID,
			AccountVersion:                           accountClaims.AccountVersion,
			AccountCredentialsTypes:                  body.AccountCredentialsTypes,
			WhitelistedDomains:                       body.WhitelistedDomains,
			RequireSoftwareStatementCredentialTypes:  body.RequireSoftwareStatementCredentialTypes,
			SoftwareStatementVerificationMethods:     body.SoftwareStatementVerificationMethods,
			RequireInitialAccessTokenCredentialTypes: body.RequireInitialAccessTokenCredentialTypes,
			InitialAccessTokenGenerationMethods:      body.InitialAccessTokenGenerationMethods,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if created {
		logResponse(logger, ctx, fiber.StatusCreated)
		return ctx.Status(fiber.StatusCreated).JSON(&dto)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&dto)
}

func (c *Controllers) GetAccountDynamicRegistrationConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(
		requestID,
		accountDynamicRegistrationConfigsLocation,
		"GetAccountDynamicRegistrationConfig",
	)
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	dto, serviceErr := c.services.GetAccountDynamicRegistrationConfig(
		ctx.UserContext(),
		services.GetAccountDynamicRegistrationConfigOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&dto)
}
