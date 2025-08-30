// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const (
	oauthDynamicRegistration string = "oauth_dynamic_registration"

	accountsIATCookieSuffix    string = "_acc_iat"
	accountsIAT2FACookieSuffix string = "_acc_iat_2fa"
)

func (c *Controllers) OAuthDynamicRegistrationIATAuth(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistrationIATAuth")
	logRequest(logger, ctx)

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ClientID:        ctx.Query("client_id"),
		ResponseType:    ctx.Query("response_type"),
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           ctx.Query("state"),
		RedirectURI:     ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), qPrms); err != nil {
		return validationErrorHTMLResponse(logger, ctx, exceptions.ValidationResponseLocationQuery, err)
	}

	redirectURL, serviceErr := c.services.InitiateOAuthDynamicRegistrationIATAuth(
		ctx.UserContext(),
		services.InitiateOAuthDynamicRegistrationIATAuthOptions{
			RequestID:       requestID,
			Domain:          qPrms.ClientID,
			State:           qPrms.State,
			SessionKey:      ctx.Cookies(c.cookieName + accountsIATCookieSuffix),
			RefreshToken:    ctx.Cookies(c.cookieName + refreshCookieSuffix),
			Challenge:       qPrms.Challenge,
			ChallengeMethod: qPrms.ChallengeMethod,
			RedirectURI:     qPrms.RedirectURI,
			BackendDomain:   c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect(redirectURL, fiber.StatusFound)
}

func (c *Controllers) OAuthDynamicRegistrationIATLoginGet(ctx *fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistrationIATLoginGet")
	logRequest(logger, ctx)

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ClientID:        ctx.Query("client_id"),
		ResponseType:    ctx.Query("response_type"),
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           ctx.Query("state"),
		RedirectURI:     ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.UserContext(), qPrms); err != nil {
		return validationErrorHTMLResponse(logger, ctx, exceptions.ValidationResponseLocationQuery, err)
	}

	loginHTML, serviceErr := c.services.OAuthDynamicRegistrationIATAuthRender(
		ctx.UserContext(),
		services.OAuthDynamicRegistrationIATAuthRenderOptions{
			RequestID:           requestID,
			State:               qPrms.State,
			CodeChallenge:       qPrms.Challenge,
			CodeChallengeMethod: qPrms.ChallengeMethod,
			RedirectURI:         qPrms.RedirectURI,
			Domain:              qPrms.ClientID,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).Type("html").SendString(loginHTML)
}

func (c *Controllers) saveAccountIATCookie(
	ctx *fiber.Ctx,
	sessionKey string,
) {
	ctx.Cookie(&fiber.Cookie{
		Name:  c.cookieName + accountsIATCookieSuffix,
		Value: sessionKey,
		Path: paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken +
			paths.OAuthAuth,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.GetOAuthCodeTTL()),
	})
}

func (c *Controllers) removeAccountIATCookie(ctx *fiber.Ctx) {
	ctx.Cookie(&fiber.Cookie{
		Name:  c.cookieName + accountsIATCookieSuffix,
		Value: "",
		Path: paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken +
			paths.OAuthAuth,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteNoneMode,
		MaxAge:   -1,
	})
}

func (c *Controllers) saveAccountIAT2FACookie(
	ctx *fiber.Ctx,
	sessionID string,
	clientID string,
) {
	ctx.Cookie(&fiber.Cookie{
		Name:  c.cookieName + accountsIAT2FACookieSuffix,
		Value: sessionID,
		Path: paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken +
			clientID + paths.AuthLogin + paths.Auth2FA,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.GetOAuthCodeTTL()),
	})
}
