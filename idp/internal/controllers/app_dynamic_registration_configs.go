// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v3"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	appDynamicRegistrationConfigsLocation string = "app_dynamic_registration_configs"
)

func (c *Controllers) UpsertAppDynamicRegistrationConfig(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(
		requestID,
		appDynamicRegistrationConfigsLocation,
		"UpsertAppDynamicRegistrationConfig",
	)
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AppDynamicRegistrationConfigBody)
	if err := ctx.Bind().Body(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.Context(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	dto, created, serviceErr := c.services.SaveAppDynamicRegistrationConfig(
		ctx.Context(),
		services.SaveAppDynamicRegistrationConfigOptions{
			RequestID:                            requestID,
			AccountPublicID:                      accountClaims.AccountID,
			AccountVersion:                       accountClaims.AccountVersion,
			AllowedAppTypes:                      body.AllowedAppTypes,
			DefaultAllowUserRegistration:         body.DefaultAllowUserRegistration,
			DefaultAuthProviders:                 body.DefaultAuthProviders,
			DefaultUsernameColumn:                body.DefaultUsernameColumn,
			DefaultAllowedScopes:                 body.DefaultAllowedScopes,
			DefaultScopes:                        body.DefaultScopes,
			RequireVerifiedDomainsAppTypes:       body.RequireVerifiedDomainsAppTypes,
			RequireSoftwareStatementAppTypes:     body.RequireSoftwareStatementAppTypes,
			SoftwareStatementVerificationMethods: body.SoftwareStatementVerificationMethods,
			RequireInitialAccessTokenAppTypes:    body.RequireInitialAccessTokenAppTypes,
			InitialAccessTokenGenerationMethods:  body.InitialAccessTokenGenerationMethods,
			InitialAccessTokenTtl:                body.InitialAccessTokenTtl,
			InitialAccessTokenMaxUses:            body.InitialAccessTokenMaxUses,
			AllowedGrantTypes:                    body.AllowedGrantTypes,
			AllowedResponseTypes:                 body.AllowedResponseTypes,
			AllowedTokenEndpointAuthMethods:      body.AllowedTokenEndpointAuthMethods,
			MaxRedirectUris:                      body.MaxRedirectUris,
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

func (c *Controllers) GetAppDynamicRegistrationConfig(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(
		requestID,
		appDynamicRegistrationConfigsLocation,
		"GetAppDynamicRegistrationConfig",
	)
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	dto, serviceErr := c.services.GetAppDynamicRegistrationConfig(
		ctx.Context(),
		services.GetAppDynamicRegistrationConfigOptions{
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

func (c *Controllers) DeleteAppDynamicRegistrationConfig(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(
		requestID,
		appDynamicRegistrationConfigsLocation,
		"DeleteAppDynamicRegistrationConfig",
	)
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	serviceErr = c.services.DeleteAppDynamicRegistrationConfig(
		ctx.Context(),
		services.DeleteAppDynamicRegistrationConfigOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
