// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const authLocation string = "auth"

func (c *Controllers) saveAccountRefreshCookie(ctx *fiber.Ctx, token string) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.refreshCookieName,
		Value:    token,
		Path:     "/auth",
		HTTPOnly: true,
		SameSite: "None",
		Secure:   true,
		MaxAge:   int(c.services.GetRefreshTTL()),
	})
}

func (c *Controllers) clearAccountRefreshCookie(ctx *fiber.Ctx) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.refreshCookieName,
		Value:    "",
		HTTPOnly: true,
		Secure:   true,
		SameSite: "None",
		MaxAge:   -1,
	})
}

func (c *Controllers) RegisterAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "RegisterAccount")
	logRequest(logger, ctx)

	body := new(bodies.RegisterAccountBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.RegisterAccount(ctx.UserContext(), services.RegisterAccountOptions{
		RequestID: requestID,
		Email:     body.Email,
		GivenName: body.GivenName,
		LastName:  body.FamilyName,
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}

func (c *Controllers) ConfirmAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "ConfirmAccount")
	logRequest(logger, ctx)

	body := new(bodies.ConfirmationTokenBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.ConfirmAccount(ctx.UserContext(), services.ConfirmAccountOptions{
		RequestID:         requestID,
		ConfirmationToken: body.ConfirmationToken,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) LoginAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "LoginAccount")
	logRequest(logger, ctx)

	body := new(bodies.LoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.LoginAccount(ctx.UserContext(), services.LoginAccountOptions{
		RequestID: requestID,
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

func (c *Controllers) TwoFactorLoginAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "TwoFactorLoginAccount")
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

	authDTO, serviceErr := c.services.TwoFactorLoginAccount(ctx.UserContext(), services.TwoFactorLoginAccountOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) LogoutAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "LogoutAccount")

	refreshToken := ctx.Cookies(c.refreshCookieName)
	if refreshToken == "" {
		body := new(bodies.RefreshTokenBody)
		if err := ctx.BodyParser(body); err != nil {
			return parseRequestErrorResponse(logger, ctx, err)
		}
		if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
			return validateBodyErrorResponse(logger, ctx, err)
		}

		refreshToken = body.RefreshToken
	}

	if serviceErr := c.services.LogoutAccount(ctx.UserContext(), services.LogoutAccountOptions{
		RequestID:    requestID,
		RefreshToken: refreshToken,
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) RefreshAccount(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "RefreshAccount")
	logRequest(logger, ctx)

	refreshToken := ctx.Cookies(c.refreshCookieName)
	if refreshToken == "" {
		body := new(bodies.RefreshTokenBody)
		if err := ctx.BodyParser(body); err != nil {
			return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
		}
		if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
			return validateBodyErrorResponse(logger, ctx, err)
		}

		refreshToken = body.RefreshToken
	}

	authDTO, serviceErr := c.services.RefreshTokenAccount(ctx.Context(), services.RefreshTokenAccountOptions{
		RequestID:    requestID,
		RefreshToken: refreshToken,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	c.saveAccountRefreshCookie(ctx, authDTO.RefreshToken)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ForgoutAccountPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "ForgoutAccountPassword")
	logRequest(logger, ctx)

	body := new(bodies.ForgoutPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.ForgoutAccountPassword(ctx.UserContext(), services.ForgoutAccountPasswordOptions{
		RequestID: requestID,
		Email:     body.Email,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}

func (c *Controllers) ResetAccountPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, authLocation, "ResetAccountPassword")
	logRequest(logger, ctx)

	body := new(bodies.ResetPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.ResetAccountPassword(ctx.UserContext(), services.ResetAccountPasswordOptions{
		RequestID:  requestID,
		ResetToken: body.ResetToken,
		Password:   body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}
