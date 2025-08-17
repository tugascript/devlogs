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

const (
	accountCredentialsRegistrationDomainsLocation string = "account_credentials_registration_domains"
)

func (c *Controllers) CreateAccountCredentialsRegistrationDomain(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "CreateAccountDynamicRegistrationDomain")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateDynamicRegistrationDomainBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	domainDTO, serviceErr := c.services.CreateAccountCredentialsRegistrationDomain(
		ctx.UserContext(),
		services.CreateAccountCredentialsRegistrationDomainOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			Domain:          body.Domain,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(domainDTO)
}

func (c *Controllers) ListAccountCredentialsRegistrationDomains(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "ListAccountCredentialsRegistrationDomains")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	queryParams := params.DynamicRegistrationDomainQueryParams{
		Limit:  ctx.QueryInt("limit", 10),
		Offset: ctx.QueryInt("offset", 0),
		Order:  ctx.Query("order", "date"),
		Search: ctx.Query("search"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	var domains []dtos.DynamicRegistrationDomainDTO
	var count int64
	if queryParams.Search != "" {
		domains, count, serviceErr = c.services.FilterAccountCredentialsRegistrationDomains(
			ctx.UserContext(),
			services.FilterAccountCredentialsRegistrationDomainsOptions{
				RequestID:       requestID,
				AccountPublicID: accountClaims.AccountID,
				Search:          queryParams.Search,
				Limit:           int32(queryParams.Limit),
				Offset:          int32(queryParams.Offset),
				Order:           queryParams.Order,
			},
		)
	} else {
		domains, count, serviceErr = c.services.ListAccountCredentialsRegistrationDomains(
			ctx.UserContext(),
			services.ListAccountCredentialsRegistrationDomainsOptions{
				RequestID:       requestID,
				AccountPublicID: accountClaims.AccountID,
				Limit:           int32(queryParams.Limit),
				Offset:          int32(queryParams.Offset),
				Order:           queryParams.Order,
			},
		)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dtos.NewPaginationDTO(
		domains,
		count,
		c.backendDomain,
		paths.AccountsBase+paths.CredentialsBase+paths.DynamicRegistrationBase+paths.Domains,
		queryParams.Limit,
		queryParams.Offset,
		"order", queryParams.Order,
	))
}

func (c *Controllers) GetAccountCredentialsRegistrationDomain(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "GetAccountCredentialsRegistrationDomain")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.DynamicRegistrationDomainURLParams{Domain: ctx.Params("domain")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	domainDTO, serviceErr := c.services.GetAccountCredentialsRegistrationDomain(
		ctx.UserContext(),
		services.GetAccountCredentialsRegistrationDomainOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Domain:          urlParams.Domain,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(domainDTO)
}

func (c *Controllers) DeleteAccountCredentialsRegistrationDomain(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "DeleteAccountCredentialsRegistrationDomain")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.DynamicRegistrationDomainURLParams{Domain: ctx.Params("domain")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	if serviceErr := c.services.DeleteAccountCredentialsRegistrationDomain(
		ctx.UserContext(),
		services.DeleteAccountCredentialsRegistrationDomainOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Domain:          urlParams.Domain,
		},
	); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) VerifyAccountCredentialsRegistrationDomain(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "VerifyAccountCredentialsRegistrationDomain")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.DynamicRegistrationDomainURLParams{Domain: ctx.Params("domain")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	domainDTO, serviceErr := c.services.VerifyAccountCredentialsRegistrationDomain(
		ctx.UserContext(),
		services.VerifyAccountCredentialsRegistrationDomainOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Domain:          urlParams.Domain,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(domainDTO)
}

func (c *Controllers) UpsertAccountCredentialsRegistrationDomainCode(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "UpsertAccountCredentialsRegistrationDomain")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateDynamicRegistrationDomainBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	domainDTO, serviceErr := c.services.SaveAccountCredentialsRegistrationDomainCode(
		ctx.UserContext(),
		services.SaveAccountCredentialsRegistrationDomainCodeOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			Domain:          body.Domain,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(domainDTO)
}

func (c *Controllers) GetAccountCredentialsRegistrationDomainCode(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "GetAccountCredentialsRegistrationDomainCode")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.DynamicRegistrationDomainURLParams{Domain: ctx.Params("domain")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	codeDTO, serviceErr := c.services.GetAccountCredentialsRegistrationDomainCode(
		ctx.UserContext(),
		services.GetAccountCredentialsRegistrationDomainCodeOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Domain:          urlParams.Domain,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(codeDTO)
}

func (c *Controllers) DeleteAccountCredentialsRegistrationDomainCode(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsRegistrationDomainsLocation, "DeleteAccountCredentialsRegistrationDomainCode")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.DynamicRegistrationDomainURLParams{Domain: ctx.Params("domain")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	if serviceErr := c.services.DeleteAccountCredentialsRegistrationDomainCode(
		ctx.UserContext(),
		services.DeleteAccountCredentialsRegistrationDomainCodeOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Domain:          urlParams.Domain,
		},
	); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
