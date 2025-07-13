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

const usersAuthLocation string = "users_auth"

func (c *Controllers) RegisterUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersAuthLocation, "RegisterUser")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	appClaims, serviceErr := getAppClaims(ctx)
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

	userSchema, serviceErr := c.services.GetOIDCConfigUserStruct(ctx.UserContext(), services.GetOIDCConfigUserStructOptions{
		RequestID: requestID,
		AccountID: accountID,
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
		AccountID:       accountID,
		AccountUsername: accountUsername,
		AppClientID:     appClaims.ClientID,
		AppVersion:      appClaims.Version,
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

	appClaims, serviceErr := getAppClaims(ctx)
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
		AccountID:         accountID,
		AccountUsername:   accountUsername,
		AppClientID:       appClaims.ClientID,
		AppVersion:        appClaims.Version,
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

	appClaims, serviceErr := getAppClaims(ctx)
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
		AccountID:       accountID,
		AccountUsername: accountUsername,
		AppClientID:     appClaims.ClientID,
		AppVersion:      appClaims.Version,
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

	userClaims, appClaims, serviceErr := getUserPurposeClaims(ctx)
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

	authDTO, serviceErr := c.services.TwoFactorLoginUser(ctx.UserContext(), services.TwoFactorLoginUserOptions{
		RequestID:       requestID,
		AccountID:       accountID,
		AccountUsername: accountUsername,
		AppClientID:     appClaims.ClientID,
		AppVersion:      appClaims.Version,
		UserPublicID:    userClaims.UserID,
		UserVersion:     userClaims.UserVersion,
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

	userClaims, appClaims, _, serviceErr := getUserAccessClaims(ctx)
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
		RequestID:    requestID,
		UserPublicID: userClaims.UserID,
		AppClientID:  appClaims.ClientID,
		Token:        body.RefreshToken,
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

	appClaims, serviceErr := getAppClaims(ctx)
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
		AccountID:       accountID,
		AccountUsername: accountUsername,
		AppClientID:     appClaims.ClientID,
		AppVersion:      appClaims.Version,
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

	appClaims, serviceErr := getAppClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.ForgotPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	messageDTO, serviceErr := c.services.ForgotUserPassword(ctx.UserContext(), services.ForgotUserPasswordOptions{
		RequestID:       requestID,
		AccountID:       accountID,
		AccountUsername: accountUsername,
		AppClientID:     appClaims.ClientID,
		AppVersion:      appClaims.Version,
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

	appClaims, serviceErr := getAppClaims(ctx)
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
		RequestID:   requestID,
		AccountID:   accountID,
		AppClientID: appClaims.ClientID,
		AppVersion:  appClaims.Version,
		ResetToken:  body.ResetToken,
		Password:    body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&messageDTO)
}
