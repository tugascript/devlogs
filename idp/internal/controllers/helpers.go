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
	"net/url"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/services/templates"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	cacheControlNoStore string = "no-store, no-cache, must-revalidate, private"

	refreshCookieSuffix = "_rt"

	grantTypeRefresh           string = "refresh_token"
	grantTypeAuthorization     string = "authorization_code"
	grantTypeClientCredentials string = "client_credentials"
	grantTypeJwtBearer         string = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

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

func validationErrorException(location string, err error) *exceptions.ValidationErrorResponse {
	var errs validator.ValidationErrors
	ok := errors.As(err, &errs)
	if !ok {
		return exceptions.NewEmptyValidationErrorResponse(location)
	}

	return exceptions.ValidationErrorResponseFromErr(&errs, location)
}

func validateErrorJSONResponse(logger *slog.Logger, ctx *fiber.Ctx, location string, err error) error {
	logger.WarnContext(ctx.UserContext(), "Failed to validate request", "error", err)
	logResponse(logger, ctx, fiber.StatusBadRequest)
	return ctx.
		Status(fiber.StatusBadRequest).
		JSON(validationErrorException(location, err))
}

func validateBodyErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorJSONResponse(logger, ctx, exceptions.ValidationResponseLocationBody, err)
}

func validateURLParamsErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorJSONResponse(logger, ctx, exceptions.ValidationResponseLocationParams, err)
}

func validateQueryParamsErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	return validateErrorJSONResponse(logger, ctx, exceptions.ValidationResponseLocationQuery, err)
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

func serviceErrorHTMLResponse(logger *slog.Logger, ctx *fiber.Ctx, serviceErr *exceptions.ServiceError) error {
	status := exceptions.NewRequestErrorStatus(serviceErr.Code)
	errHtml, err := templates.BuildErrorTemplate(
		templates.ErrorTemplateOptions{
			Status:       status,
			ErrorCode:    serviceErr.Code,
			MessageTitle: serviceErr.Message,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx.UserContext(), "Failed to build error template", "error", err)
		logResponse(logger, ctx, fiber.StatusInternalServerError)
		return ctx.Status(fiber.StatusInternalServerError).
			Type("html").
			SendString(templates.InternalServerErrorTemplate)
	}

	logResponse(logger, ctx, status)
	return ctx.Status(status).Type("html").SendString(errHtml)
}

func oauthErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, message string) error {
	resErr := exceptions.NewOAuthError(message)

	switch message {
	case exceptions.OAuthErrorInvalidRequest, exceptions.OAuthErrorInvalidGrant,
		exceptions.OAuthErrorInvalidScope, exceptions.OAuthErrorUnsupportedGrantType,
		exceptions.OAuthErrorInvalidRedirectURI, exceptions.OAuthErrorInvalidClientMetadata,
		exceptions.OAuthErrorInvalidSoftwareStatement, exceptions.OAuthErrorUnapprovedSoftwareStatement,
		exceptions.OAuthErrorUnsupportedResponseType:
		logResponse(logger, ctx, fiber.StatusBadRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(&resErr)
	case exceptions.OAuthErrorUnauthorizedClient, exceptions.OAuthErrorAccessDenied, exceptions.OAuthErrorInvalidToken:
		logResponse(logger, ctx, fiber.StatusUnauthorized)
		return ctx.Status(fiber.StatusUnauthorized).JSON(&resErr)
	case exceptions.OAuthErrorServerError:
		logResponse(logger, ctx, fiber.StatusInternalServerError)
		return ctx.Status(fiber.StatusInternalServerError).JSON(&resErr)
	default:
		logResponse(logger, ctx, fiber.StatusBadRequest)
		resErr = exceptions.NewOAuthError(exceptions.OAuthErrorInvalidRequest)
		return ctx.Status(fiber.StatusBadRequest).JSON(&resErr)
	}
}

func parseRequestErrorResponse(logger *slog.Logger, ctx *fiber.Ctx, err error) error {
	logger.WarnContext(ctx.UserContext(), "Failed to parse request", "error", err)
	logResponse(logger, ctx, fiber.StatusBadRequest)
	return ctx.
		Status(fiber.StatusBadRequest).
		JSON(exceptions.NewEmptyValidationErrorResponse(exceptions.ValidationResponseLocationBody))
}

func (c *Controllers) redirectErrorCallback(
	logger *slog.Logger,
	ctx *fiber.Ctx,
	redirectURI string,
	state string,
	errMsg string,
) error {
	qPrams := make(url.Values)
	qPrams.Add("error", errMsg)
	if state != "" {
		qPrams.Add("state", state)
	}
	qPrams.Add("iss", fmt.Sprintf("https://%s", c.backendDomain))
	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(redirectURI+"?"+qPrams.Encode(), fiber.StatusFound)
}

func (c *Controllers) redirectServiceErrorCallback(
	logger *slog.Logger,
	ctx *fiber.Ctx,
	redirectURI string,
	state string,
	serviceErr *exceptions.ServiceError,
) error {
	switch serviceErr.Code {
	case exceptions.CodeUnauthorized, exceptions.CodeForbidden:
		return c.redirectErrorCallback(logger, ctx, redirectURI, state, exceptions.OAuthErrorAccessDenied)
	case exceptions.CodeNotFound, exceptions.CodeValidation:
		return c.redirectErrorCallback(logger, ctx, redirectURI, state, exceptions.OAuthErrorInvalidRequest)
	default:
		return c.redirectErrorCallback(logger, ctx, redirectURI, state, exceptions.OAuthErrorServerError)
	}
}

func dynamicRegistrationServiceError(
	logger *slog.Logger,
	ctx *fiber.Ctx,
	serviceErr *exceptions.ServiceError,
) error {
	switch serviceErr.Code {
	case exceptions.CodeUnauthorized, exceptions.CodeForbidden:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnauthorizedClient)
	case exceptions.CodeNotFound, exceptions.CodeValidation:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	case exceptions.CodeInvalidToken:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidSoftwareStatement)
	case exceptions.CodeUnauthorizedToken:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnapprovedSoftwareStatement)
	default:
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}
}
