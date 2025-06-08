// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
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
	if body.UserData == nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(
			exceptions.NewEmptyValidationErrorResponse(exceptions.ValidationResponseLocationBody),
		)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	schemaType, serviceErr := c.services.GetOIDCConfigUserStruct(
		ctx.UserContext(),
		services.GetOIDCConfigUserStructOptions{
			RequestID: requestID,
			AccountID: accountID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	schemaValue, serviceErrWithFields := c.services.UnmarshalSchemaBody(ctx.UserContext(), services.UnmarshalSchemaBodyOptions{
		RequestID:  requestID,
		SchemaType: schemaType,
		Data:       body.UserData,
	})
	if serviceErrWithFields != nil {
		return serviceErrorWithFieldsResponse(logger, ctx, serviceErrWithFields)
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

func (c *Controllers) ListUsers(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "ListUsers")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	queryParams := params.ListUsersQueryParams{
		Limit:  ctx.QueryInt("limit", 10),
		Offset: ctx.QueryInt("offset", 0),
		Order:  ctx.Query("order", "date"),
		Search: ctx.Query("search"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(ctx.UserContext(), services.GetAccountIDByPublicIDAndVersionOptions{
		RequestID: requestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	var users []dtos.UserDTO
	var count int64

	if queryParams.Search != "" {
		users, count, serviceErr = c.services.FilterUsers(ctx.UserContext(), services.FilterUsersOptions{
			RequestID: requestID,
			AccountID: accountID,
			Offset:    int32(queryParams.Offset),
			Limit:     int32(queryParams.Limit),
			Order:     queryParams.Order,
			Search:    queryParams.Search,
		})
	} else {
		users, count, serviceErr = c.services.ListUsers(ctx.UserContext(), services.ListUsersOptions{
			RequestID: requestID,
			AccountID: accountID,
			Offset:    int32(queryParams.Offset),
			Limit:     int32(queryParams.Limit),
			Order:     queryParams.Order,
		})
	}

	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dtos.NewPaginationDTO(
		users,
		count,
		c.backendDomain,
		paths.UsersBase,
		queryParams.Limit,
		queryParams.Offset,
		"order", queryParams.Order,
		"search", queryParams.Search,
	))
}

func (c *Controllers) GetUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "GetUser")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.GetUserURLParams{
		UserIDOrUsername: ctx.Params("userIDOrUsername"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userID, err := strconv.ParseInt(urlParams.UserIDOrUsername, 10, 32)
	if err == nil {
		userDTO, serviceErr := c.services.GetUserByID(ctx.UserContext(), services.GetUserByIDOptions{
			RequestID: requestID,
			UserID:    int32(userID),
			AccountID: accountID,
		})
		if serviceErr != nil {
			return serviceErrorResponse(logger, ctx, serviceErr)
		}

		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.Status(fiber.StatusOK).JSON(&userDTO)
	}

	userDTO, serviceErr := c.services.GetUserByUsername(
		ctx.UserContext(),
		services.GetUserByUsernameOptions{
			RequestID: requestID,
			AccountID: accountID,
			Username:  urlParams.UserIDOrUsername,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&userDTO)
}

func (c *Controllers) UpdateUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "UpdateUser")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userID, err := ctx.ParamsInt("userID")
	if err != nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(
			exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationParams, []exceptions.FieldError{
				{
					Param:   "userID",
					Message: "Invalid user ID",
					Value:   userID,
				},
			}),
		)
	}
	urlParams := params.MutateUserURLParams{
		UserID: int32(userID),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.UpdateUserBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	schemaType, serviceErr := c.services.GetOIDCConfigUserStruct(
		ctx.UserContext(),
		services.GetOIDCConfigUserStructOptions{
			RequestID: requestID,
			AccountID: accountID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	schemaValue, serviceErrWithFields := c.services.UnmarshalSchemaBody(ctx.UserContext(), services.UnmarshalSchemaBodyOptions{
		RequestID:  requestID,
		SchemaType: schemaType,
		Data:       body.UserData,
	})
	if serviceErrWithFields != nil {
		return serviceErrorWithFieldsResponse(logger, ctx, serviceErrWithFields)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), schemaValue.Interface()); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	userDTO, serviceErr := c.services.UpdateUser(ctx.UserContext(), services.UpdateUserOptions{
		RequestID: requestID,
		AccountID: accountID,
		UserID:    int32(urlParams.UserID),
		Email:     body.Email,
		Username:  body.Username,
		UserData:  schemaValue,
		IsActive:  body.IsActive,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&userDTO)
}

func (c *Controllers) UpdateUserPassword(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "UpdateUserPassword")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userID, err := ctx.ParamsInt("userID")
	if err != nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(
			exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationParams, []exceptions.FieldError{
				{
					Param:   "userID",
					Message: "Invalid user ID",
					Value:   userID,
				},
			}),
		)
	}
	urlParams := params.MutateUserURLParams{
		UserID: int32(userID),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.UpdateUserPasswordBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userDTO, serviceErr := c.services.UpdateUserPassword(ctx.UserContext(), services.UpdateUserPasswordOptions{
		RequestID: requestID,
		AccountID: accountID,
		UserID:    int32(urlParams.UserID),
		Password:  body.Password,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&userDTO)
}

func (c *Controllers) DeleteUser(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, usersLocation, "DeleteUser")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	userID, err := ctx.ParamsInt("userID")
	if err != nil {
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(
			exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationParams, []exceptions.FieldError{
				{
					Param:   "userID",
					Message: "Invalid user ID",
					Value:   userID,
				},
			}),
		)
	}
	urlParams := params.MutateUserURLParams{
		UserID: int32(userID),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), &urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountID, serviceErr := c.services.GetAccountIDByPublicIDAndVersion(
		ctx.UserContext(),
		services.GetAccountIDByPublicIDAndVersionOptions{
			RequestID: requestID,
			PublicID:  accountClaims.AccountID,
			Version:   accountClaims.AccountVersion,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	if serviceErr := c.services.DeleteUser(ctx.UserContext(), services.DeleteUserOptions{
		RequestID: requestID,
		AccountID: accountID,
		UserID:    int32(urlParams.UserID),
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
