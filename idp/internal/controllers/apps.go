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
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const appsLocation string = "apps"

func (c *Controllers) GetApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "GetApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.GetAppByClientIDAndAccountPublicID(
		ctx.UserContext(),
		services.GetAppByClientIDAndAccountPublicIDOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			ClientID:        urlParams.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDTO)
}

func (c *Controllers) CreateApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "CreateApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateAppBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateApp(ctx.UserContext(), services.CreateAppOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		Name:            body.Name,
		Type:            body.Type,
		UsernameColumn:  body.UsernameColumn,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) UpdateApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "UpdateApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.UpdateAppBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.UpdateApp(ctx.UserContext(), services.UpdateAppOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		ClientID:        urlParams.ClientID,
		Name:            body.Name,
		ConfirmationURI: body.ConfirmationURI,
		ResetURI:        body.ResetURI,
		CallbackUris:    body.CallbackURIs,
		LogoutUris:      body.LogoutURIs,
		DefaultScopes:   body.DefaultScopes,
		AuthProviders:   body.Providers,
		IDTokenTtl:      body.IDTokenTTL,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDTO)
}

func (c *Controllers) RefreshAppSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "RefreshAppSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.UpdateAppSecret(ctx.UserContext(), services.UpdateAppSecretOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		ClientID:        urlParams.ClientID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDTO)
}

func (c *Controllers) DeleteApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "DeleteApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	serviceErr = c.services.DeleteApp(ctx.UserContext(), services.DeleteAppOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		ClientID:        urlParams.ClientID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) ListApps(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "ListApps")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	queryParams := params.GetAppsQueryParams{
		Limit:  ctx.QueryInt("limit", 10),
		Offset: ctx.QueryInt("offset", 0),
		Name:   ctx.Query("name"),
		Order:  ctx.Query("order", "date"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	var apps []dtos.AppDTO
	var count int64

	if queryParams.Name != "" {
		apps, count, serviceErr = c.services.FilterAccountApps(ctx.UserContext(), services.FilterAccountAppsOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int64(queryParams.Offset),
			Limit:           int64(queryParams.Limit),
			Order:           queryParams.Order,
			Name:            queryParams.Name,
		})
	} else {
		apps, count, serviceErr = c.services.ListAccountApps(ctx.UserContext(), services.ListAccountAppsOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int64(queryParams.Offset),
			Limit:           int64(queryParams.Limit),
			Order:           queryParams.Order,
		})
	}

	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dtos.NewPaginationDTO(
		apps,
		count,
		c.backendDomain,
		paths.AppsBase,
		queryParams.Limit,
		queryParams.Offset,
		"order", queryParams.Order,
		"name", queryParams.Name,
	))
}
