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

	accountDTO, serviceErr := c.services.GetAccountByPublicIDAndVersion(ctx.UserContext(), services.GetAccountByPublicIDAndVersionOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
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
		Version:     accountClaims.AccountVersion,
		Password:    body.OldPassword,
		NewPassword: body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.RefreshToken != "" {
		c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	}

	logResponse(logger, ctx, fiber.StatusOK)
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
		Version:   accountClaims.AccountVersion,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) CreateAccountPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "CreateAccountPassword")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreatePasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.CreateAccountPassword(ctx.UserContext(), services.CreateAccountPasswordOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
		Password:  body.Password,
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
		Version:   accountClaims.AccountVersion,
		Email:     body.Email,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.RefreshToken != "" {
		c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	}

	logResponse(logger, ctx, fiber.StatusOK)
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
		Version:   accountClaims.AccountVersion,
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
		Version:    accountClaims.AccountVersion,
		GivenName:  body.GivenName,
		FamilyName: body.FamilyName,
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

	deleted, authDTO, serviceErr := c.services.DeleteAccount(ctx.UserContext(), services.DeleteAccountOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if !deleted && authDTO.AccessToken != "" {
		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.Status(fiber.StatusOK).JSON(&authDTO)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	c.clearAccountRefreshCookie(ctx)
	return ctx.SendStatus(fiber.StatusNoContent)
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
		Version:   accountClaims.AccountVersion,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.clearAccountRefreshCookie(ctx)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) UpdateAccount2FA(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "UpdateAccount2FA")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdateTwoFactorBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.UpdateAccount2FA(ctx.UserContext(), services.UpdateAccount2FAOptions{
		RequestID:     requestID,
		PublicID:      accountClaims.AccountID,
		Version:       accountClaims.AccountVersion,
		TwoFactorType: body.TwoFactorType,
		Password:      body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.RefreshToken != "" {
		c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ConfirmUpdateAccount2FA(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "ConfirmUpdateAccount2FA")
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

	authDTO, serviceErr := c.services.ConfirmUpdateAccount2FA(ctx.UserContext(), services.ConfirmUpdateAccount2FAOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) UpdateAccountUsername(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "UpdateAccountUsername")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.UpdateAccountUsernameBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.UpdateAccountUsername(ctx.UserContext(), services.UpdateAccountUsernameOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
		Username:  body.Username,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if authDTO.RefreshToken != "" {
		c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ConfirmUpdateAccountUsername(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountsLocation, "ConfirmUpdateAccountUsername")
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

	authDTO, serviceErr := c.services.ConfirmUpdateAccountUsername(
		ctx.UserContext(),
		services.ConfirmUpdateAccountUsernameOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
			Code:      body.Code,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}
