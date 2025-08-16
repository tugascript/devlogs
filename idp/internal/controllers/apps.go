// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
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
	appTypeMCP     AppType = "mcp"
)

func (c *Controllers) createWebApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createWebApp")
	logRequest(logger, ctx)

	body := new(bodies.CreateAppBodyWeb)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateWebApp(ctx.UserContext(), services.CreateWebAppOptions{
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		UsernameColumn:        baseBody.UsernameColumn,
		AuthMethod:            body.TokenEndpointAuthMethod,
		Algorithm:             body.Algorithm,
		ClientURI:             baseBody.ClientURI,
		Domain:                baseBody.Domain,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		RedirectURIs:          body.RedirectURIs,
		ResponseTypes:         body.ResponseTypes,
		AuthProviders:         baseBody.AuthProviders,
		Transport:             body.Transport,
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

	appDTO, serviceErr := c.services.CreateSPANativeApp(ctx.UserContext(), services.CreateSPANativeAppOptions{
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		AppType:               database.AppTypeSpa,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		Domain:                baseBody.Domain,
		Transport:             body.Transport,
		UsernameColumn:        baseBody.UsernameColumn,
		ResponseTypes:         body.ResponseTypes,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		RedirectURIs:          body.RedirectURIs,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		AuthProviders:         baseBody.AuthProviders,
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

	appDTO, serviceErr := c.services.CreateSPANativeApp(ctx.UserContext(), services.CreateSPANativeAppOptions{
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		UsernameColumn:        baseBody.UsernameColumn,
		AppType:               database.AppTypeNative,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		Domain:                baseBody.Domain,
		Transport:             body.Transport,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		RedirectURIs:          body.RedirectURIs,
		ResponseTypes:         body.ResponseTypes,
		AuthProviders:         baseBody.AuthProviders,
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
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		UsernameColumn:        baseBody.UsernameColumn,
		AuthMethod:            body.TokenEndpointAuthMethod,
		Algorithm:             body.Algorithm,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Domain:                body.Domain,
		Transport:             body.Transport,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		AuthProviders:         baseBody.AuthProviders,
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
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		UsernameColumn:        baseBody.UsernameColumn,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Domain:                baseBody.Domain,
		BackendDomain:         c.backendDomain,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		AssociatedApps:        body.AssociatedApps,
		AuthProviders:         baseBody.AuthProviders,
		Transport:             body.Transport,
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
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		Name:                  baseBody.Name,
		CreationMethod:        database.CreationMethodManual,
		AccountVersion:        accountClaims.AccountVersion,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		AuthMethod:            body.TokenEndpointAuthMethod,
		Algorithm:             body.Algorithm,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		UsersAuthMethod:       body.UsersAuthMethod,
		Domain:                baseBody.Domain,
		Transport:             body.Transport,
		AllowedDomains:        body.AllowedDomains,
		AuthProviders:         baseBody.AuthProviders,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}

func (c *Controllers) createMCPApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	baseBody *bodies.CreateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "createMCPApp")

	body := new(bodies.CreateAppBodyMCP)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.CreateMCPApp(ctx.UserContext(), services.CreateMCPAppOptions{
		RequestID:             requestID,
		AccountPublicID:       accountClaims.AccountID,
		AccountVersion:        accountClaims.AccountVersion,
		CreationMethod:        database.CreationMethodManual,
		Name:                  baseBody.Name,
		AllowUserRegistration: baseBody.AllowUserRegistration,
		UsernameColumn:        baseBody.UsernameColumn,
		ClientURI:             baseBody.ClientURI,
		LogoURI:               baseBody.LogoURI,
		TOSURI:                baseBody.TOSURI,
		PolicyURI:             baseBody.PolicyURI,
		Contacts:              baseBody.Contacts,
		SoftwareID:            baseBody.SoftwareID,
		SoftwareVersion:       baseBody.SoftwareVersion,
		Scopes:                baseBody.Scopes,
		DefaultScopes:         baseBody.DefaultScopes,
		Transport:             body.Transport,
		AuthMethod:            body.TokenEndpointAuthMethod,
		Algorithm:             body.Algorithm,
		RedirectURIs:          body.RedirectURIs,
		ResponseTypes:         body.ResponseTypes,
		Domain:                baseBody.Domain,
		AuthProviders:         baseBody.AuthProviders,
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
	case appTypeMCP:
		return c.createMCPApp(ctx, requestID, &accountClaims, body)
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
		Type:   ctx.Query("type"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	var apps []dtos.AppDTO
	var count int64

	if queryParams.Name != "" && queryParams.Type != "" {
		apps, count, serviceErr = c.services.FilterAccountAppsByNameAndType(ctx.UserContext(), services.FilterAccountAppsByNameAndTypeOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int32(queryParams.Offset),
			Limit:           int32(queryParams.Limit),
			Order:           queryParams.Order,
			Name:            queryParams.Name,
		})
	} else if queryParams.Name != "" {
		apps, count, serviceErr = c.services.FilterAccountAppsByName(ctx.UserContext(), services.FilterAccountAppsByNameOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int32(queryParams.Offset),
			Limit:           int32(queryParams.Limit),
			Order:           queryParams.Order,
			Name:            queryParams.Name,
		})
	} else if queryParams.Type != "" {
		apps, count, serviceErr = c.services.FilterAccountAppsByType(ctx.UserContext(), services.FilterAccountAppsByTypeOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int32(queryParams.Offset),
			Limit:           int32(queryParams.Limit),
			Order:           queryParams.Order,
			Type:            queryParams.Type,
		})
	} else {
		apps, count, serviceErr = c.services.ListAccountApps(ctx.UserContext(), services.ListAccountAppsOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          int32(queryParams.Offset),
			Limit:           int32(queryParams.Limit),
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

func (c *Controllers) updateWebApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateWebApp")

	body := new(bodies.UpdateAppBodyWeb)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateWebSPANativeApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateWebSPANativeAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			UsernameColumn:        baseBody.UsernameColumn,
			Name:                  baseBody.Name,
			Domain:                baseBody.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			RedirectURIs:          body.RedirectURIs,
			ResponseTypes:         body.ResponseTypes,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateSPAApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateSPAApp")

	body := new(bodies.UpdateAppBodySPA)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateWebSPANativeApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateWebSPANativeAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			UsernameColumn:        baseBody.UsernameColumn,
			Name:                  baseBody.Name,
			Domain:                baseBody.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			RedirectURIs:          body.RedirectURIs,
			ResponseTypes:         body.ResponseTypes,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateNativeApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateNativeApp")

	body := new(bodies.UpdateAppBodyNative)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateWebSPANativeApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateWebSPANativeAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			UsernameColumn:        baseBody.UsernameColumn,
			Name:                  baseBody.Name,
			Domain:                baseBody.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			RedirectURIs:          body.RedirectURIs,
			ResponseTypes:         body.ResponseTypes,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateServiceApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateServiceApp")

	body := new(bodies.UpdateAppBodyService)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateServiceApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateServiceAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			Name:                  baseBody.Name,
			Domain:                baseBody.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			AllowedDomains:        body.AllowedDomains,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateBackendApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateBackendApp")

	body := new(bodies.UpdateAppBodyBackend)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateBackendApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateBackendAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			UsernameColumn:        baseBody.UsernameColumn,
			Name:                  baseBody.Name,
			Domain:                body.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateDeviceApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateDeviceApp")

	body := new(bodies.UpdateAppBodyDevice)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateDeviceApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateDeviceAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			UsernameColumn:        baseBody.UsernameColumn,
			Name:                  baseBody.Name,
			Domain:                baseBody.Domain,
			Transport:             body.Transport,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			BackendDomain:         c.backendDomain,
			AssociatedApps:        body.AssociatedApps,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) updateMCPApp(
	ctx *fiber.Ctx,
	requestID string,
	accountClaims *tokens.AccountClaims,
	appDTO *dtos.AppDTO,
	baseBody *bodies.UpdateAppBodyBase,
) error {
	logger := c.buildLogger(requestID, appsLocation, "updateMCPApp")

	body := new(bodies.UpdateAppBodyMCP)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	completeAppDTO, serviceErr := c.services.UpdateMCPApp(
		ctx.UserContext(),
		appDTO,
		services.UpdateMCPAppOptions{
			RequestID:             requestID,
			AccountID:             accountID,
			Name:                  baseBody.Name,
			UsernameColumn:        baseBody.UsernameColumn,
			ClientURI:             baseBody.ClientURI,
			LogoURI:               baseBody.LogoURI,
			TOSURI:                baseBody.TOSURI,
			PolicyURI:             baseBody.PolicyURI,
			SoftwareID:            baseBody.SoftwareID,
			SoftwareVersion:       baseBody.SoftwareVersion,
			Contacts:              baseBody.Contacts,
			Domain:                baseBody.Domain,
			RedirectURIs:          body.RedirectURIs,
			ResponseTypes:         body.ResponseTypes,
			AllowUserRegistration: baseBody.AllowUserRegistration,
			AuthProviders:         baseBody.AuthProviders,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&completeAppDTO)
}

func (c *Controllers) UpdateApp(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "UpdateApp")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdateAppBodyBase)
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

	appDTO, serviceErr := c.services.GetAppByClientIDAndAccountPublicID(ctx.UserContext(), services.GetAppByClientIDAndAccountPublicIDOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		ClientID:        urlParams.ClientID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	switch appDTO.AppType {
	case database.AppTypeWeb:
		return c.updateWebApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeSpa:
		return c.updateSPAApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeNative:
		return c.updateNativeApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeBackend:
		return c.updateBackendApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeDevice:
		return c.updateDeviceApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeService:
		return c.updateServiceApp(ctx, requestID, &accountClaims, &appDTO, body)
	case database.AppTypeMcp:
		return c.updateMCPApp(ctx, requestID, &accountClaims, &appDTO, body)
	default:
		logger.ErrorContext(ctx.UserContext(), "Invalid app type", "appType", appDTO.AppType)
		return serviceErrorResponse(logger, ctx, exceptions.NewInternalServerError())
	}
}

func (c *Controllers) GetAppWithRelatedConfigs(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "GetAppWithRelatedConfigs")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	appDTO, serviceErr := c.services.GetAppWithRelatedConfigs(ctx.UserContext(), services.GetAppWithRelatedConfigsOptions{
		RequestID:       requestID,
		AppClientID:     urlParams.ClientID,
		AccountPublicID: accountClaims.AccountID,
		BackendDomain:   c.backendDomain,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&appDTO)
}

func (c *Controllers) ListAppSecrets(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "ListAppSecrets")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	queryParams := params.PaginationQueryParams{
		Offset: ctx.QueryInt("offset", 0),
		Limit:  ctx.QueryInt("limit", 20),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	secretsOrKeys, count, serviceErr := c.services.ListAppCredentialsSecretsOrKeys(
		ctx.UserContext(),
		services.ListAppCredentialsSecretsOrKeysOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AppClientID:     urlParams.ClientID,
			Offset:          int32(queryParams.Offset),
			Limit:           int32(queryParams.Limit),
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	paginationDTO := dtos.NewPaginationDTO(
		secretsOrKeys,
		count,
		c.backendDomain,
		fmt.Sprintf("%s/%s/secrets", paths.AppsBase, urlParams.ClientID),
		queryParams.Limit,
		queryParams.Offset,
	)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&paginationDTO)
}

func (c *Controllers) GetAppSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "GetAppSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	secretDTO, serviceErr := c.services.GetAppCredentialsSecretOrKey(ctx.UserContext(), services.GetAppCredentialsSecretOrKeyOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AppClientID:     urlParams.ClientID,
		SecretID:        ctx.Params("secretID"),
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&secretDTO)
}

func (c *Controllers) RevokeAppSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "RevokeAppSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsSecretOrKeyURLParams{
		ClientID: ctx.Params("clientID"),
		SecretID: ctx.Params("secretID"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	secretDTO, serviceErr := c.services.RevokeAppCredentialsSecretOrKey(ctx.UserContext(), services.RevokeAppCredentialsSecretOrKeyOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AppClientID:     urlParams.ClientID,
		SecretID:        urlParams.SecretID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&secretDTO)
}

func (c *Controllers) CreateAppSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, appsLocation, "CreateAppSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{
		ClientID: ctx.Params("clientID"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.CreateCredentialsSecretBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	secretDTO, serviceErr := c.services.RotateAppCredentialsSecretOrKey(
		ctx.UserContext(),
		services.RotateAppCredentialsSecretOrKeyOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			AppClientID:     urlParams.ClientID,
			Algorithm:       body.Algorithm,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&secretDTO)
}
