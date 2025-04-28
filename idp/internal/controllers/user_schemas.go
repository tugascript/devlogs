// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"context"
	"fmt"
	"regexp"

	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	userSchemasLocation string = "user_schemas"

	snakeCaseRegex = `^[a-z]+(_[a-z]+)*$`

	snakeCaseErrorMessage       = "must be in snake_case format"
	userSchemaFieldErrorMessage = "must be either string, int, float or bool"
	defaultValueErrorMessage    = "default value must be of the same type as the field type"
)

var snakeCaseRegexCompiled = regexp.MustCompile(snakeCaseRegex)

func isValidSnakeCase(s string) bool {
	return len(s) > 0 && snakeCaseRegexCompiled.MatchString(s)
}

func validateDefaultValue(field bodies.UserSchemaFieldBody) error {
	// If no default value is set, it's valid
	if field.Default == nil {
		return nil
	}

	switch field.Type {
	case "string":
		if _, ok := field.Default.(string); !ok {
			return fmt.Errorf("default value must be a string")
		}
	case "int":
		// Check for float64 since JSON unmarshaling typically converts numbers to float64
		if f, ok := field.Default.(float64); ok {
			if f != float64(int(f)) {
				return fmt.Errorf("default value must be an integer")
			}
		} else if _, ok := field.Default.(int); !ok {
			return fmt.Errorf("default value must be an integer")
		}
	case "float":
		if _, ok := field.Default.(float64); !ok {
			// Also accept int as valid for float
			if _, ok := field.Default.(int); !ok {
				return fmt.Errorf("default value must be a float")
			}
		}
	case "bool":
		if _, ok := field.Default.(bool); !ok {
			return fmt.Errorf("default value must be a boolean")
		}
	default:
		return fmt.Errorf("unknown field type: %s", field.Type)
	}

	return nil
}

func (c *Controllers) validateUserSchemaBody(
	ctx context.Context,
	body map[string]bodies.UserSchemaFieldBody,
) (map[string]services.UserSchemaField, *exceptions.ValidationErrorResponse) {
	schema := make(map[string]services.UserSchemaField, len(body))
	fieldErrors := make([]exceptions.FieldError, 0)

	for fieldName, field := range body {
		if !isValidSnakeCase(fieldName) {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fieldName,
				Value:   fieldName,
				Message: snakeCaseErrorMessage,
			})
		}
		if err := c.validate.StructCtx(ctx, field); err != nil {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fmt.Sprintf("%s.type", fieldName),
				Value:   field.Type,
				Message: userSchemaFieldErrorMessage,
			})
		}
		if err := validateDefaultValue(field); err != nil {
			fieldErrors = append(fieldErrors, exceptions.FieldError{
				Param:   fmt.Sprintf("%s.default", fieldName),
				Value:   fmt.Sprintf("%v", field.Default),
				Message: defaultValueErrorMessage,
			})
		}

		if len(fieldErrors) == 0 {
			schema[fieldName] = services.UserSchemaField{
				Type:     field.Type,
				Unique:   field.Unique,
				Required: field.Required,
				Default:  field.Default,
			}
		}
	}

	if len(fieldErrors) > 0 {
		return nil, exceptions.NewValidationErrorResponse(exceptions.ValidationResponseLocationBody, fieldErrors)
	}

	return schema, nil
}

func (c *Controllers) CreateUserSchema(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, userSchemasLocation, "CreateUserSchema")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := make(map[string]bodies.UserSchemaFieldBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}

	schema, errorRes := c.validateUserSchemaBody(ctx.UserContext(), body)
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

	body := make(map[string]bodies.UserSchemaFieldBody)
	if err := ctx.BodyParser(&body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}

	schema, errorRes := c.validateUserSchemaBody(ctx.UserContext(), body)
	if errorRes != nil {
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
