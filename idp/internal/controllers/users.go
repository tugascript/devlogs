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

const usersLocation string = "users"

func (c *Controllers) CreateUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "GetUser")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.CreateUserBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}
	if body.DataBody == nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(
			exceptions.NewEmptyValidationErrorResponse(exceptions.ValidationResponseLocationBody),
		)
	}

	accountID := int32(accountClaims.ID)
	schemaDTO, schemaType, serviceErr := c.services.GetUserSchemaStruct(
		ctx.UserContext(),
		services.GetOrCreateUserSchemaOptions{
			RequestID: requestID,
			AccountID: accountID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	schemaValue, serviceErr := c.services.UnmarshalSchemaBody(ctx.UserContext(), services.UnmarshalSchemaBodyOptions{
		RequestID:  requestID,
		SchemaDTO:  schemaDTO,
		SchemaType: schemaType,
		Data:       body.DataBody,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), schemaValue.Interface()); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	userDTO, serviceErr := c.services.CreateUser(ctx.UserContext(), services.CreateUserOptions{
		RequestID: requestID,
		AccountID: accountID,
		Email:     body.Email,
		Username:  body.Username,
		Password:  body.Password,
		UserData:  schemaValue,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&userDTO)
}
