// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const (
	accountCredentialsLocation string = "account_credentials"

	accountCredentialsKeysCacheControl string = "public, max-age=900, must-revalidate"
)

func (c *Controllers) CreateAccountCredentials(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "CreateAccountCredentials")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateAccountCredentialsBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.CreateAccountCredentials(
		ctx.UserContext(),
		services.CreateAccountCredentialsOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			Alias:           body.Alias,
			Scopes:          body.Scopes,
			AuthMethod:      body.AuthMethod,
			Issuers:         body.Issuers,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
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
	if err := c.validate.StructCtx(ctx.UserContext(), &queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTOs, count, serviceErr := c.services.ListAccountCredentialsByAccountPublicID(
		ctx.UserContext(),
		services.ListAccountCredentialsByAccountPublicID{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			Offset:          queryParams.Offset,
			Limit:           queryParams.Limit,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	paginationDTO := dtos.NewPaginationDTO(
		accountKeysDTOs,
		count,
		c.backendDomain,
		paths.AccountsBase+paths.CredentialsBase,
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
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.GetAccountCredentialsByClientIDAndAccountPublicID(
		ctx.UserContext(),
		services.GetAccountCredentialsByClientIDAndAccountPublicIDOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			ClientID:        urlParams.ClientID,
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
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.UpdateAccountCredentialsBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.UpdateAccountCredentials(
		ctx.UserContext(),
		services.UpdateAccountCredentialsScopesOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			ClientID:        urlParams.ClientID,
			Scopes:          body.Scopes,
			Alias:           body.Alias,
			Issuers:         body.Issuers,
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
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AccountVersion:  accountClaims.AccountVersion,
		ClientID:        urlParams.ClientID,
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) ListAccountCredentialsSecrets(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "ListAccountCredentialsSecrets")
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

	secretsOrKeys, count, serviceErr := c.services.ListAccountCredentialsSecretsOrKeys(
		ctx.UserContext(),
		services.ListAccountCredentialsSecretsOrKeysOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			ClientID:        urlParams.ClientID,
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
		fmt.Sprintf("%s%s/%s/secrets", paths.AccountsBase, paths.CredentialsBase, urlParams.ClientID),
		queryParams.Limit,
		queryParams.Offset,
	)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&paginationDTO)
}

func (c *Controllers) CreateAccountCredentialsSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "CreateAccountCredentialsSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.CredentialsURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.CreateCredentialsSecretBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	secretDTO, serviceErr := c.services.RotateAccountCredentialsSecret(
		ctx.UserContext(),
		services.RotateAccountCredentialsSecretOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			ClientID:        urlParams.ClientID,
			Algorithm:       body.Algorithm,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	ctx.Set(fiber.HeaderCacheControl, cacheControlNoStore)
	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&secretDTO)
}

func (c *Controllers) GetAccountCredentialsSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "GetAccountCredentialsSecret")
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

	secretDTO, serviceErr := c.services.GetAccountCredentialsSecretOrKey(
		ctx.UserContext(),
		services.GetAccountCredentialsSecretOrKeyOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			ClientID:        urlParams.ClientID,
			SecretID:        urlParams.SecretID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&secretDTO)
}

func (c *Controllers) RevokeAccountCredentialsSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "RevokeAccountCredentialsSecret")
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

	secretDTO, serviceErr := c.services.RevokeAccountCredentialsSecretOrKey(
		ctx.UserContext(),
		services.RevokeAccountCredentialsSecretOrKeyOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			ClientID:        urlParams.ClientID,
			SecretID:        urlParams.SecretID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&secretDTO)
}

func (c *Controllers) ListAccountCredentialsKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountCredentialsLocation, "ListAccountCredentialsKeys")
	logRequest(logger, ctx)

	urlParams := params.AccountURLParams{AccountPublicID: ctx.Params("accountPublicID")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountPublicID, err := uuid.Parse(urlParams.AccountPublicID)
	if err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	keys, etag, serviceErr := c.services.ListActiveAccountCredentialsKeysWithCache(
		ctx.UserContext(),
		services.ListActiveAccountCredentialsKeysWithCacheOptions{
			RequestID:       requestID,
			AccountPublicID: accountPublicID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if match := ctx.Get(fiber.HeaderIfNoneMatch); match == etag {
		logResponse(logger, ctx, fiber.StatusNotModified)
		return ctx.SendStatus(fiber.StatusNotModified)
	}

	ctx.Set(fiber.HeaderCacheControl, accountCredentialsKeysCacheControl)
	ctx.Set(fiber.HeaderETag, etag)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&keys)
}
