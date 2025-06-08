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
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const accountsLocation string = "accounts"

func (c *Controllers) GetCurrentAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "GetCurrentAccount")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	accountDTO, serviceErr := c.services.GetAccountByPublicID(ctx.UserContext(), services.GetAccountByPublicIDOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountDTO)
}

func (c *Controllers) UpdateAccountPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "UpdateAccountPassword")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdatePasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.UpdateAccountPassword(ctx.UserContext(), services.UpdateAccountPasswordOptions{
		RequestID:   requestID,
		PublicID:    accountClaims.AccountID,
		Password:    body.OldPassword,
		NewPassword: body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.AccessToken != "" {
		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.Status(fiber.StatusOK).JSON(dtos.NewMessageDTO("Password update innitiated. Please 2FA login."))
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ConfirmUpdateAccountPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "ConfirmUpdateAccountPassword")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.TwoFactorLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.ConfirmUpdateAccountPassword(ctx.UserContext(), services.ConfirmUpdateAccountPasswordOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) UpdateAccountEmail(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "UpdateAccountEmail")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdateEmailBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.UpdateAccountEmail(ctx.UserContext(), services.UpdateAccountEmailOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Email:     body.Email,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.AccessToken != "" {
		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.Status(fiber.StatusOK).JSON(dtos.NewMessageDTO("Email update innitiated. Please 2FA login."))
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ConfirmUpdateAccountEmail(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "ConfirmUpdateAccountEmail")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.TwoFactorLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.ConfirmUpdateAccountEmail(ctx.UserContext(), services.ConfirmUpdateAccountEmailOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) UpdateAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "UpdateAccount")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdateAccountBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountDTO, serviceErr := c.services.UpdateAccount(ctx.UserContext(), services.UpdateAccountOptions{
		RequestID:  requestID,
		PublicID:   accountClaims.AccountID,
		GivenName:  body.GivenName,
		FamilyName: body.FamilyName,
		Username:   body.Username,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountDTO)
}

func (c *Controllers) DeleteAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "DeleteAccount")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.DeleteWithPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	deleted, serviceErr := c.services.DeleteAccount(ctx.UserContext(), services.DeleteAccountOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if !deleted {
		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.Status(fiber.StatusOK).JSON(dtos.NewMessageDTO("Account deletion initiated. Please 2FA login."))
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.clearAccountRefreshCookie(ctx)
	return ctx.Status(fiber.StatusOK).JSON(dtos.NewMessageDTO("Account deleted successfully"))
}

func (c *Controllers) ConfirmDeleteAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "ConfirmDeleteAccount")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.TwoFactorLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	serviceErr = c.services.ConfirmDeleteAccount(ctx.UserContext(), services.ConfirmDeleteAccountOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.clearAccountRefreshCookie(ctx)
	return ctx.SendStatus(fiber.StatusNoContent)
}
