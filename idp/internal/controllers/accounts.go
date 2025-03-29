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

	accountDTO, serviceErr := c.services.GetAccountByID(ctx.UserContext(), services.GetAccountByIDOptions{
		RequestID: requestID,
		ID:        int32(accountClaims.ID),
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
		ID:          int32(accountClaims.ID),
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
	saveAccountRefreshCookie(ctx, "refresh_token", authDTO.RefreshToken)
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
		ID:        int32(accountClaims.ID),
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	saveAccountRefreshCookie(ctx, "refresh_token", authDTO.RefreshToken)
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
		ID:        int32(accountClaims.ID),
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
	saveAccountRefreshCookie(ctx, "refresh_token", authDTO.RefreshToken)
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
		ID:        int32(accountClaims.ID),
		Code:      body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	saveAccountRefreshCookie(ctx, "refresh_token", authDTO.RefreshToken)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}
