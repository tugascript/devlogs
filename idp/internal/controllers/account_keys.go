package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const accountKeysLocation string = "account_keys"

func (c *Controllers) CreateAccountKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "CreateAccountKeys")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.AccountKeysBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.CreateAccountKeys(ctx.UserContext(), services.CreateAccountKeysOptions{
		RequestID: requestID,
		AccountID: int32(accountClaims.ID),
		Scopes:    body.Scopes,
	})
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(&accountKeysDTO)
}

func (c *Controllers) ListAccountKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "ListAccountKeys")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	queryParams := params.PaginationQueryParams{
		Offset: ctx.QueryInt("offset", 0),
		Limit:  ctx.QueryInt("limit", 20),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), queryParams); err != nil {
		return validateQueryParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTOs, count, serviceErr := c.services.ListAccountKeysByAccountID(
		ctx.UserContext(),
		services.ListAccountKeyByAccountID{
			RequestID: requestID,
			AccountID: accountClaims.ID,
			Offset:    queryParams.Offset,
			Limit:     queryParams.Limit,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	paginationDTO := dtos.NewPaginationDTO(
		accountKeysDTOs,
		count,
		c.backendDomain,
		paths.AccountKeysBase,
		queryParams.Limit,
		queryParams.Offset,
	)
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&paginationDTO)
}

func (c *Controllers) GetSingleAccountKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "GetSingleAccountKeys")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.AccountKeysURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.GetAccountKeysByClientIDAndAccountID(
		ctx.UserContext(),
		services.GetAccountKeysByClientIDAndAccountIDOptions{
			RequestID: requestID,
			AccountID: accountClaims.ID,
			ClientID:  urlParams.ClientID,
		},
	)

	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) RefreshAccountKeysSecret(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "RefreshAccountKeysSecret")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.AccountKeysURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.UpdateAccountKeysSecret(
		ctx.UserContext(),
		services.UpdateAccountKeysSecretOptions{
			RequestID: requestID,
			AccountID: accountClaims.ID,
			ClientID:  urlParams.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) UpdateAccountKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "UpdateAccountKeys")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.AccountKeysURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	body := new(bodies.AccountKeysBody)
	if err := ctx.BodyParser(body); err != nil {
		return parseRequestErrorResponse(logger, ctx, err)
	}
	if err := c.validate.StructCtx(ctx.UserContext(), body); err != nil {
		return validateBodyErrorResponse(logger, ctx, err)
	}

	accountKeysDTO, serviceErr := c.services.UpdateAccountKeysScopes(
		ctx.UserContext(),
		services.UpdateAccountKeysScopesOptions{
			RequestID: requestID,
			AccountID: accountClaims.ID,
			ClientID:  urlParams.ClientID,
			Scopes:    body.Scopes,
		},
	)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(&accountKeysDTO)
}

func (c *Controllers) DeleteAccountKeys(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, accountKeysLocation, "DeleteAccountKeys")
	logRequest(logger, ctx)

	accountClaims, serviceErr := getAccountClaims(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	urlParams := params.AccountKeysURLParams{ClientID: ctx.Params("clientID")}
	if err := c.validate.StructCtx(ctx.UserContext(), urlParams); err != nil {
		return validateURLParamsErrorResponse(logger, ctx, err)
	}

	if serviceErr := c.services.DeleteAccountKeys(ctx.UserContext(), services.DeleteAccountKeysOptions{
		RequestID: requestID,
		AccountID: accountClaims.ID,
		ClientID:  urlParams.ClientID,
	}); serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
