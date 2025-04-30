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

const (
	userSchemasLocation string = "user_schemas"
)

func (c *Controllers) CreateUserSchema(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, userSchemasLocation, "CreateUserSchema")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := make(map[string]bodies.SchemaFieldBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}

	schema, errorRes := c.ValidateSchemaBody(ctx.UserContext(), body)
	if errorRes != nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(errorRes)
	}

	userSchemaDTO, serviceErr := c.services.CreateUserSchema(ctx.UserContext(), services.CreateUserSchemaOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		Schema:    schema,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&userSchemaDTO)
}

func (c *Controllers) GetUserSchema(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, userSchemasLocation, "GetUserSchema")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userSchemaDTO, serviceErr := c.services.GetOrCreateUserSchema(
		ctx.UserContext(),
		services.GetOrCreateUserSchemaOptions{
			RequestID: requestID,
			AccountID: int32(accountClaims.ID),
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&userSchemaDTO)
}

func (c *Controllers) UpdateUserSchema(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, userSchemasLocation, "UpdateUserSchema")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := make(map[string]bodies.SchemaFieldBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}

	schema, errorRes := c.ValidateSchemaBody(ctx.UserContext(), body)
	if errorRes != nil {
		logger.WarnContext(ctx.UserContext(), "invalid schema body", errorRes)
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(errorRes)
	}

	userSchemaDTO, serviceErr := c.services.UpdateUserSchema(ctx.UserContext(), services.UpdateUserSchemaOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		Schema:    schema,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&userSchemaDTO)
}
