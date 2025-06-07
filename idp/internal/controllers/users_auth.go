// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const usersAuthLocation string = "users_auth"

func (c *Controllers) RegisterUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "RegisterUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, _, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.RegisterUserBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	userSchema, serviceErr := c.services.GetOIDCConfigUserStruct(ctx.UserContext(), services.GetOrCreateOIDCConfigOptions{
		RequestID: requestID,
		AccountID: int32(accountID),
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userValue, serviceErrWithFields := c.services.UnmarshalSchemaBody(ctx.UserContext(), services.UnmarshalSchemaBodyOptions{
		RequestID:  requestID,
		SchemaType: userSchema,
		Data:       body.UserData,
	})
	if serviceErrWithFields != nil {
		return serviceErrorWithFieldsResponse(logger, ctx, serviceErrWithFields)
	}

	messageDTO, serviceErr := c.services.RegisterUser(ctx.UserContext(), services.RegisterUserOptions{
		RequestID:       requestID,
		AccountID:       int32(accountID),
		AccountUsername: accountUsername,
		AppID:           appID,
		Email:           body.Email,
		Username:        body.Username,
		Password:        body.Password,
		UserData:        userValue,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&messageDTO)
}

func (c *Controllers) ConfirmUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "ConfirmUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, _, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.ConfirmationTokenBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.ConfirmAuthUser(ctx.UserContext(), services.ConfirmAuthUserOptions{
		RequestID:         requestID,
		AccountID:         int32(accountID),
		AccountUsername:   accountUsername,
		AppID:             appID,
		ConfirmationToken: body.ConfirmationToken,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) LoginUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "LoginUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, _, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.LoginUserBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.LoginUser(ctx.UserContext(), services.LoginUserOptions{
		RequestID:       requestID,
		AccountID:       int32(accountID),
		AccountUsername: accountUsername,
		AppID:           appID,
		UsernameOrEmail: body.UsernameOrEmail,
		Password:        body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) TwoFactorLoginUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "TwoFactorLoginUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userClaims, appClaims, userScopes, serviceErr := getUserClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}
	if !slices.Contains(userScopes, tokens.UserScope2FA) {
		return serviceErrorResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	body := new(bodies.TwoFactorLoginBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.TwoFactorLoginUser(ctx.UserContext(), services.TwoFactorLoginUserOptions{
		RequestID:       requestID,
		AccountID:       int32(accountID),
		AccountUsername: accountUsername,
		AppID:           appClaims.AppID,
		UserID:          userClaims.UserID,
		Version:         userClaims.UserVersion,
		Code:            body.Code,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) LogoutUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "LogoutUser")
	logRequest(logger, ctx)

	userClaims, appClaims, _, serviceErr := getUserClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.RefreshTokenBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	if serviceErr := c.services.LogoutUser(ctx.UserContext(), services.LogoutUserOptions{
		RequestID: requestID,
		UserID:    userClaims.UserID,
		AppID:     appClaims.AppID,
		Token:     body.RefreshToken,
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) RefreshUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "RefreshUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, _, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.RefreshTokenBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	authDTO, serviceErr := c.services.RefreshUserAccess(ctx.UserContext(), services.RefreshUserAccessOptions{
		RequestID:       requestID,
		AccountID:       int32(accountID),
		AccountUsername: accountUsername,
		AppID:           appID,
		Token:           body.RefreshToken,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&authDTO)
}

func (c *Controllers) ForgotUserPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "ForgotUserPassword")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, appClientID, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.ForgoutPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.ForgoutUserPassword(ctx.UserContext(), services.ForgoutUserPasswordOptions{
		RequestID:       requestID,
		AccountID:       int32(accountID),
		AccountUsername: accountUsername,
		AppID:           appID,
		AppClientID:     appClientID,
		Email:           body.Email,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}

func (c *Controllers) ResetUserPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "ResetUserPassword")
	logRequest(logger, ctx)

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appID, _, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.ResetPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.ResetUserPassword(ctx.UserContext(), services.ResetUserPasswordOptions{
		RequestID:  requestID,
		AccountID:  int32(accountID),
		AppID:      appID,
		ResetToken: body.ResetToken,
		Password:   body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}
