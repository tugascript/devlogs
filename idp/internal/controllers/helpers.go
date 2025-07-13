// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const cacheControlNoStore string = "no-store"

func (c *Controllers) buildLogger(
	requestID,
	location,
	method string,
) *slog.Logger {
	return utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  location,
		Method:    method,
		RequestID: requestID,
	})
}

func logRequest(logger *slog.Logger, ctx *fiber.Ctx) {
	logger.InfoContext(
		ctx.UserContext(),
		fmt.Sprintf("Request: %s %s", ctx.Method(), ctx.Path()),
	)
}

func getRequestID(ctx *fiber.Ctx) string {
	return ctx.Get("requestid", uuid.NewString())
}

func logResponse(logger *slog.Logger, ctx *fiber.Ctx, status int) {
	logger.InfoContext(
		ctx.UserContext(),
		fmt.Sprintf("Response: %s %s", ctx.Method(), ctx.Path()),
		"status", status,
	)
}

func validateErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, location string, err error) error {
	logger.WarnContext(ctx.UserContext(), "Failed to validate request", "error", err)
	logResponse(logger, ctx, fiber.StatusBadRequest)

	var errs validator.ValidationErrors
	ok := errors.As(err, &errs)
	if !ok {
		return ctx.
			Status(fiber.StatusBadRequest).
			JSON(exceptions.NewEmptyValidationErrorResponse(location))
	}

	return ctx.
		Status(fiber.StatusBadRequest).
		JSON(exceptions.ValidationErrorResponseFromErr(&errs, location))
}

func validateBodyErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorResponse(logger, ctx, exceptions.ValidationResponseLocationBody, err)
}

func validateURLParamsErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorResponse(logger, ctx, exceptions.ValidationResponseLocationParams, err)
}

func validateQueryParamsErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorResponse(logger, ctx, exceptions.ValidationResponseLocationQuery, err)
}

func serviceErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, serviceErr *exceptions.ServiceError) error {
	status := exceptions.NewRequestErrorStatus(serviceErr.Code)
	resErr := exceptions.NewErrorResponse(serviceErr)
	logResponse(logger, ctx, status)
	return ctx.Status(status).JSON(&resErr)
}

func serviceErrorWithFieldsResponse(logger *slog.Logger, ctx *fiber.Ctx, serviceErr *exceptions.ServicErrorWithFields) error {
	logResponse(logger, ctx, fiber.StatusBadRequest)
	return ctx.Status(fiber.StatusBadRequest).JSON(exceptions.NewValidationErrorResponse(
		exceptions.ValidationResponseLocationBody,
		serviceErr.Fields,
	))
}

func oauthErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, message string) error {
	resErr := exceptions.NewOAuthError(message)
	logResponse(logger, ctx, fiber.StatusBadRequest)
	return ctx.Status(fiber.StatusBadRequest).JSON(&resErr)
}

func parseRequestErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	logger.WarnContext(ctx.UserContext(), "Failed to parse request", "error", err)
	logResponse(logger, ctx, fiber.StatusBadRequest)
	return ctx.
		Status(fiber.StatusBadRequest).
		JSON(exceptions.NewEmptyValidationErrorResponse(exceptions.ValidationResponseLocationBody))
}

// func parseBasicAuthHeader(ctx *fiber.Ctx) (string, string, *exceptions.ServiceError) {
// 	ah := ctx.Get("Authorization")
// 	if ah == "" {
// 		return "", "", exceptions.NewUnauthorizedError()
// 	}

// 	ahSlice := strings.Split(strings.TrimSpace(ah), " ")
// 	if len(ahSlice) != 2 || utils.Lowered(ahSlice[0]) != "basic" {
// 		return "", "", exceptions.NewUnauthorizedError()
// 	}

// 	decoded, err := base64.StdEncoding.DecodeString(ahSlice[1])
// 	if err != nil {
// 		return "", "", exceptions.NewUnauthorizedError()
// 	}

// 	decodedSlice := strings.Split(string(decoded), ":")
// 	if len(ahSlice) != 2 {
// 		return "", "", exceptions.NewUnauthorizedError()
// 	}

// 	return decodedSlice[0], decodedSlice[1], nil
// }
