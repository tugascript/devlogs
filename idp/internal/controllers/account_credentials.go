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

const accountCredentialsLocation string = "account_credentials"

func (c *Controllers) CreateAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "CreateAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AccountCredentialsBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.CreateAccountCredentials(ctx.UserContext(), services.CreateAccountCredentialsOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		Alias:     body.Alias,
		Scopes:    body.Scopes,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&accountKeysDTO)
}

func (c *Controllers) ListAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "ListAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	queryParams := params.PaginationQueryParams{
		Offset: ctx.QueryInt("offset", 0),
		Limit:  ctx.QueryInt("limit", 20),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTOs, count, serviceErr := c.services.ListAccountCredentialsByAccountID(
		ctx.UserContext(),
		services.ListAccountKeyByAccountID{
			RequestID: requestID,
			AccountID: accountClaims.ID,
			Offset:    queryParams.Offset,
			Limit:     queryParams.Limit,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	paginationDTO := dtos.NewPaginationDTO(
		accountKeysDTOs,
		count,
		c.backendDomain,
		paths.AccountCredentialsBase,
		queryParams.Limit,
		queryParams.Offset,
	)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&paginationDTO)
}

func (c *Controllers) GetSingleAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "GetSingleAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.GetAccountCredentialsByClientIDAndAccountID(
		ctx.UserContext(),
		services.GetAccountCredentialsByClientIDAndAccountIDOptions{
			RequestID: requestID,
			AccountID: int32(accountClaims.ID),
			ClientID:  urlParams.ClientID,
		},
	)

	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) RefreshAccountCredentialsSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "RefreshAccountCredentialsSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.UpdateAccountCredentialsSecret(
		ctx.UserContext(),
		services.UpdateAccountCredentialsSecretOptions{
			RequestID: requestID,
			AccountID: int32(accountClaims.ID),
			ClientID:  urlParams.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) UpdateAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "UpdateAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.AccountCredentialsBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.UpdateAccountCredentials(
		ctx.UserContext(),
		services.UpdateAccountCredentialsScopesOptions{
			RequestID: requestID,
			AccountID: int32(accountClaims.ID),
			ClientID:  urlParams.ClientID,
			Scopes:    body.Scopes,
			Alias:     body.Alias,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) DeleteAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "DeleteAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	if serviceErr := c.services.DeleteAccountCredentials(ctx.UserContext(), services.DeleteAccountCredentialsOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		ClientID:  urlParams.ClientID,
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
