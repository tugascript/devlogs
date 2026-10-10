// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"net/url"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

type implicitAuthorizationQuery struct {
	ClientID     string `validate:"required,min=1"`
	ResponseType string `validate:"required,eq=id_token"`
	RedirectURI  string `validate:"required,uri"`
	Scope        string `validate:"required,min=1"`
	State        string `validate:"omitempty,min=1"`
	Nonce        string `validate:"required,min=1"`
}

func (c *Controllers) AppOAuthImplicitAuthorization(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthLocation, "AppOAuthImplicitAuthorization")
	logRequest(logger, ctx)

	accountUsername, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	query := implicitAuthorizationQuery{
		ClientID:     ctx.Query("client_id"),
		ResponseType: ctx.Query("response_type"),
		RedirectURI:  ctx.Query("redirect_uri"),
		Scope:        ctx.Query("scope"),
		State:        ctx.Query("state"),
		Nonce:        ctx.Query("nonce"),
	}
	if err := c.validate.StructCtx(ctx.Context(), query); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}
	if !slices.Contains(strings.Fields(query.Scope), "openid") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidScope)
	}

	userClaims, appClaims, _, serviceErr := c.services.ProcessUserAuthHeader(ctx.Context(), services.ProcessUserAuthHeaderOptions{
		RequestID:  requestID,
		AuthHeader: ctx.Get("Authorization"),
		AccountID:  accountID,
		TokenType:  tokens.AuthTokenTypeAccess,
	})
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}

	idToken, serviceErr := c.services.ImplicitOAuthAuthorization(ctx.Context(), services.ImplicitOAuthAuthorizationOptions{
		RequestID:       requestID,
		AccountID:       accountID,
		AccountUsername: accountUsername,
		BackendDomain:   c.backendDomain,
		ClientID:        query.ClientID,
		RedirectURI:     query.RedirectURI,
		Nonce:           query.Nonce,
		UserClaims:      userClaims,
		AppClaims:       appClaims,
	})
	if serviceErr != nil {
		switch serviceErr.Code {
		case exceptions.CodeUnauthorized:
			return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
		case exceptions.CodeForbidden:
			return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnauthorizedClient)
		default:
			return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
		}
	}

	callback, err := url.Parse(query.RedirectURI)
	if err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRedirectURI)
	}
	fragment := url.Values{"id_token": {idToken}}
	if query.State != "" {
		fragment.Set("state", query.State)
	}
	callback.Fragment = fragment.Encode()

	ctx.Set(fiber.HeaderCacheControl, "no-store")
	ctx.Set("Pragma", "no-cache")
	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(callback.String())
}
