// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const appDesignsLocation string = "app_designs"

func (c *Controllers) CreateAppDesign(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appDesignsLocation, "CreateAppDesign")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AppDesignBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDesignDTO, serviceErr := c.services.CreateAppDesign(
		ctx.UserContext(),
		services.AppDesignOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			AppClientID:     urlParams.ClientID,
			LightColors:     services.ColorsOptions(body.LightColors),
			DarkColors: func() *services.ColorsOptions {
				if body.DarkColors == nil {
					return nil
				}
				return &services.ColorsOptions{
					PrimaryColor:    body.DarkColors.PrimaryColor,
					SecondaryColor:  body.DarkColors.SecondaryColor,
					BackgroundColor: body.DarkColors.BackgroundColor,
					TextColor:       body.DarkColors.TextColor,
				}
			}(),
			LogoURL:    body.LogoURL,
			FaviconURL: body.FaviconURL,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDesignDTO)
}

func (c *Controllers) GetAppDesign(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appDesignsLocation, "GetAppDesign")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDesignDTO, serviceErr := c.services.GetAppDesign(
		ctx.UserContext(),
		services.GetAppDesignByAppClientIDOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AppClientID:     urlParams.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDesignDTO)
}

func (c *Controllers) UpdateAppDesign(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appDesignsLocation, "UpdateAppDesign")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AppDesignBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDesignDTO, serviceErr := c.services.UpdateAppDesign(
		ctx.UserContext(),
		services.AppDesignOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			AppClientID:     urlParams.ClientID,
			LightColors:     services.ColorsOptions(body.LightColors),
			DarkColors: func() *services.ColorsOptions {
				if body.DarkColors == nil {
					return nil
				}
				return &services.ColorsOptions{
					PrimaryColor:    body.DarkColors.PrimaryColor,
					SecondaryColor:  body.DarkColors.SecondaryColor,
					BackgroundColor: body.DarkColors.BackgroundColor,
					TextColor:       body.DarkColors.TextColor,
				}
			}(),
			LogoURL:    body.LogoURL,
			FaviconURL: body.FaviconURL,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDesignDTO)
}

func (c *Controllers) DeleteAppDesign(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appDesignsLocation, "DeleteAppDesign")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	serviceErr = c.services.DeleteAppDesign(
		ctx.UserContext(),
		services.DeleteAppDesignOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccoutVersion:   accountClaims.AccountVersion,
			AppClientID:     urlParams.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
