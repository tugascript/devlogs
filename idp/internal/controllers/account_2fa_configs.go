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
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const account2FAConfigsLocation = "account_2fa_configs"

func (c *Controllers) GetDefaultAccount2FAConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "GetDefaultAccount2FAConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	account2FAConfigDTO, serviceErr := c.services.GetDefaultAccount2FAConfig(ctx.UserContext(), services.GetDefaultAccount2FAConfigOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&account2FAConfigDTO)
}

func (c *Controllers) GetAccount2FAConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "GetAccount2FAConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.GetAccount2FAConfigURLParams{TwoFAType: ctx.Params("twoFAType")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	twoFAType, serviceErr := services.Map2FAType(urlParams.TwoFAType)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	account2FAConfigDTO, serviceErr := c.services.GetAccount2FAConfig(ctx.UserContext(), services.GetAccount2FAConfigOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		TwoFAType:       twoFAType,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&account2FAConfigDTO)
}

func (c *Controllers) CreateAccount2FAConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "CreateAccount2FAConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.Account2FAConfigBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	account2FAConfigDTO, serviceErr := c.services.CreateAccount2FAConfig(
		ctx.UserContext(),
		services.CreateAccount2FAConfigOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			TwoFAType:       body.TwoFAType,
			IsDefault:       body.IsDefault,
		})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&account2FAConfigDTO)
}

func (c *Controllers) SetAccount2FAConfigDefault(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "SetAccount2FAConfigDefault")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.GetAccount2FAConfigURLParams{TwoFAType: ctx.Params("twoFAType")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	account2FAConfigDTO, serviceErr := c.services.SetAccount2FAConfigDefault(
		ctx.UserContext(),
		services.SetAccount2FAConfigDefaultOptions{
			RequestID:       requestID,
			AccountPublicID: accountClaims.AccountID,
			AccountVersion:  accountClaims.AccountVersion,
			TwoFAType:       urlParams.TwoFAType,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&account2FAConfigDTO)
}

func (c *Controllers) DeleteAccount2FAConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "DeleteAccount2FAConfig")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.GetAccount2FAConfigURLParams{TwoFAType: ctx.Params("twoFAType")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	account2FAConfigDTO, serviceErr := c.services.DeleteAccount2FAConfig(ctx.UserContext(), services.DeleteAccount2FAConfigOptions{
		RequestID:       requestID,
		AccountPublicID: accountClaims.AccountID,
		AccountVersion:  accountClaims.AccountVersion,
		TwoFAType:       urlParams.TwoFAType,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&account2FAConfigDTO)
}

func (c *Controllers) ConfirmDeleteAccount2FAConfig(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, account2FAConfigsLocation, "ConfirmDeleteAccount2FAConfig")
	logRequest(logger, ctx)

	accountClaims, twoFAType, serviceErr := getAccounts2FAClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.GetAccount2FAConfigURLParams{TwoFAType: ctx.Params("twoFAType")}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}
	if string(twoFAType) != urlParams.TwoFAType {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	body := new(bodies.TwoFactorLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.ConfirmDeleteAccount2FAConfig(
		ctx.UserContext(),
		services.ConfirmDeleteAccount2FAConfigOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
			TwoFAType: urlParams.TwoFAType,
			Code:      body.Code,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}
