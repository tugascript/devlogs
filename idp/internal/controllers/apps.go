// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/tugascript/devlogs/idp/internal/exceptions"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

type AppType = string

const (
	appsLocation string = "apps"

	appTypeWeb     AppType = "web"
	appTypeSPA     AppType = "spa"
	appTypeNative  AppType = "native"
	appTypeBackend AppType = "backend"
	appTypeDevice  AppType = "device"
	appTypeService AppType = "service"
)

func (c *Controllers) createWebApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createWebApp")

	body := new(bodies.CreateAppBodyWeb)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateWebApp(ctx.UserContext(), services.CreateWebAppOptions{
		RequestID:           requestID,
		AccountPublicID:     accountClaims.AccountID,
		AccountVersion:      accountClaims.AccountVersion,
		Name:                baseBody.Name,
		UsernameColumn:      body.UsernameColumn,
		AuthMethods:         body.AuthMethods,
		Algorithm:           body.Algorithm,
		ClientURI:           baseBody.ClientURI,
		CallbackURIs:        body.CallbackURLs,
		LogoutURIs:          body.LogoutURLs,
		AllowedOrigins:      body.AllowedOrigins,
		CodeChallengeMethod: body.CodeChallengeMethod,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createSPAApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createSPAOrSpaApp")

	body := new(bodies.CreateAppBodySPA)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateSPAApp(ctx.UserContext(), services.CreateSPAAppOptions{
		RequestID:           requestID,
		AccountPublicID:     accountClaims.AccountID,
		AccountVersion:      accountClaims.AccountVersion,
		Name:                baseBody.Name,
		UsernameColumn:      body.UsernameColumn,
		ClientURI:           baseBody.ClientURI,
		CallbackURIs:        body.CallbackURLs,
		LogoutURIs:          body.LogoutURLs,
		AllowedOrigins:      body.AllowedOrigins,
		CodeChallengeMethod: body.CodeChallengeMethod,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createNativeApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createNativeOrSpaApp")

	body := new(bodies.CreateAppBodyNative)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateNativeApp(ctx.UserContext(), services.CreateNativeAppOptions{
		RequestID:           requestID,
		AccountPublicID:     accountClaims.AccountID,
		AccountVersion:      accountClaims.AccountVersion,
		Name:                baseBody.Name,
		UsernameColumn:      body.UsernameColumn,
		ClientURI:           baseBody.ClientURI,
		CallbackURIs:        body.CallbackURIs,
		LogoutURIs:          body.LogoutURIs,
		CodeChallengeMethod: body.CodeChallengeMethod,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createBackendApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createBackendApp")

	body := new(bodies.CreateAppBodyBackend)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateBackendApp(ctx.UserContext(), services.CreateBackendAppOptions{
		RequestID:        requestID,
		AccountPublicID:  accountClaims.AccountID,
		AccountVersion:   accountClaims.AccountVersion,
		Name:             baseBody.Name,
		UsernameColumn:   body.UsernameColumn,
		AuthMethods:      body.AuthMethods,
		Algorithm:        body.Algorithm,
		ClientURI:        baseBody.ClientURI,
		ConfirmationURL:  body.ConfirmationURL,
		ResetPasswordURL: body.ResetPasswordURL,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createDeviceApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createDeviceOrSpaApp")

	body := new(bodies.CreateAppBodyDevice)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateDeviceApp(ctx.UserContext(), services.CreateDeviceAppOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AccountVersion:  accountClaims.AccountVersion,
		Name:            baseBody.Name,
		UsernameColumn:  body.UsernameColumn,
		ClientURI:       baseBody.ClientURI,
		BackendDomain:   c.backendDomain,
		AssociatedApps:  body.AssociatedApps,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createServiceApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createServiceApp")

	body := new(bodies.CreateAppBodyService)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateServiceApp(ctx.UserContext(), services.CreateServiceAppOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AccountVersion:  accountClaims.AccountVersion,
		Name:            baseBody.Name,
		AuthMethods:     body.AuthMethods,
		Algorithm:       body.Algorithm,
		ClientURI:       baseBody.ClientURI,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) CreateApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "CreateApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateAppBodyBase)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	switch body.Type {
	case appTypeWeb:
		return c.createWebApp(ctx, requestID, &accountClaims, body)
	case appTypeSPA:
		return c.createSPAApp(ctx, requestID, &accountClaims, body)
	case appTypeNative:
		return c.createNativeApp(ctx, requestID, &accountClaims, body)
	case appTypeBackend:
		return c.createBackendApp(ctx, requestID, &accountClaims, body)
	case appTypeDevice:
		return c.createDeviceApp(ctx, requestID, &accountClaims, body)
	case appTypeService:
		return c.createServiceApp(ctx, requestID, &accountClaims, body)
	default:
		logger.WarnContext(ctx.UserContext(), "Invalid app type", "appType", body.Type)
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(exceptions.NewValidationErrorResponse(
			exceptions.ValidationResponseLocationBody,
			[]exceptions.FieldError{
				{Param: "type", Message: "must be a valid app type", Value: body.Type},
			},
		))
	}
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
