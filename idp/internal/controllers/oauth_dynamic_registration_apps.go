// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/gofiber/fiber/v3"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func appsIATResumeURL(fields bodies.OAuthDynamicRegistrationIATAuthHiddenFieldsBody) string {
	query := url.Values{
		"client_id":      {fields.ClientID},
		"response_type":  {fields.ResponseType},
		"redirect_uri":   {fields.RedirectURI},
		"state":          {fields.State},
		"code_challenge": {fields.CodeChallenge},
	}
	if fields.CodeChallengeMethod != "" {
		query.Set("code_challenge_method", fields.CodeChallengeMethod)
	}
	return oauthDynamicRegistrationIATCookiePath() + paths.OAuthAuth + "?" + query.Encode()
}

const (
	oauthAppsDynamicRegistrationIAT string = "oauth_dynamic_registration_apps"

	appsIATCookieSuffix    string = "_app_iat"
	appsIAT2FACookieSuffix string = "_app_iat_2fa"
)

func (c *Controllers) AppsOAuthDynamicRegistrationIATAuth(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATAuth")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	baseQPrms := params.OAuthDynamicRegistrationIATAuthBaseQueryParams{
		ClientID:    ctx.Query("client_id"),
		RedirectURI: ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), baseQPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	responseType := ctx.Query("response_type")
	state := ctx.Query("state")
	if responseType != "code" {
		return c.redirectErrorCallback(logger, ctx, baseQPrms.RedirectURI, state, exceptions.OAuthErrorUnsupportedResponseType)
	}

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ResponseType:    responseType,
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           state,
	}
	if err := c.validate.StructCtx(ctx.Context(), qPrms); err != nil {
		return c.redirectErrorCallback(logger, ctx, baseQPrms.RedirectURI, state, exceptions.OAuthErrorInvalidRequest)
	}

	sessionKey := ctx.Cookies(c.cookieName + appsIATCookieSuffix)
	if sessionKey != "" {
		// This ensures that the key is only used once
		c.removeAppIATCookie(ctx)
	}

	redirectURL, serviceErr := c.services.InitiateAppsOAuthDynamicRegistrationIATAuth(
		ctx.Context(),
		services.InitiateAppsOAuthDynamicRegistrationIATAuthOptions{
			AccountID:       accountID,
			Hostname:        hostname,
			RequestID:       requestID,
			Domain:          baseQPrms.ClientID,
			Origin:          ctx.Get(fiber.HeaderOrigin),
			State:           qPrms.State,
			SessionKey:      sessionKey,
			RefreshToken:    ctx.Cookies(c.cookieName + refreshCookieSuffix),
			Challenge:       qPrms.Challenge,
			ChallengeMethod: qPrms.ChallengeMethod,
			RedirectURI:     baseQPrms.RedirectURI,
			BackendDomain:   c.backendDomain,
		},
	)
	if serviceErr != nil {
		return c.redirectServiceErrorCallback(logger, ctx, baseQPrms.RedirectURI, state, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(redirectURL)
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATLoginGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATLoginGet")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	baseQPrms := params.OAuthDynamicRegistrationIATAuthBaseQueryParams{
		ClientID:    ctx.Query("client_id"),
		RedirectURI: ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), baseQPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ResponseType:    ctx.Query("response_type"),
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           ctx.Query("state"),
	}
	if err := c.validate.StructCtx(ctx.Context(), qPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	loginHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIATAuthRender(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATAuthRenderOptions{
			AccountID:           accountID,
			Hostname:            hostname,
			RequestID:           requestID,
			ACCClientID:         uPrms.ACCClientID,
			State:               qPrms.State,
			Domain:              baseQPrms.ClientID,
			CodeChallenge:       qPrms.Challenge,
			CodeChallengeMethod: qPrms.ChallengeMethod,
			RedirectURI:         baseQPrms.RedirectURI,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).Type("html").SendString(loginHTML)
}

func (c *Controllers) saveAppIATCookie(
	ctx fiber.Ctx,
	sessionKey string,
) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + appsIATCookieSuffix,
		Value:    sessionKey,
		Path:     oauthDynamicRegistrationIATCookiePath(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.GetOAuthCodeTTL()),
	})
}

func (c *Controllers) removeAppIATCookie(ctx fiber.Ctx) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + appsIATCookieSuffix,
		Value:    "",
		Path:     oauthDynamicRegistrationIATCookiePath(),
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteNoneMode,
		MaxAge:   -1,
	})
}

func (c *Controllers) saveAppIAT2FACookie(ctx fiber.Ctx, sessionID string) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + appsIAT2FACookieSuffix,
		Value:    sessionID,
		Path:     oauthDynamicRegistrationIATCookiePath(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.Get2FATTL()),
	})
}

func (c *Controllers) removeAppIAT2FACookie(ctx fiber.Ctx) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + appsIAT2FACookieSuffix,
		Value:    "",
		Path:     oauthDynamicRegistrationIATCookiePath(),
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   -1,
	})
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATLoginPost(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATLoginPost")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnsupportedMediaTypeError("Only application/x-www-form-urlencoded is supported"))
	}

	hiddenFields := bodies.OAuthDynamicRegistrationIATAuthHiddenFieldsBody{
		CSRFToken:           ctx.FormValue("csrf_token"),
		ClientID:            ctx.FormValue("client_id"),
		ResponseType:        ctx.FormValue("response_type"),
		CodeChallenge:       ctx.FormValue("code_challenge"),
		CodeChallengeMethod: ctx.FormValue("code_challenge_method"),
		State:               ctx.FormValue("state"),
		RedirectURI:         ctx.FormValue("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &hiddenFields); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	loginBody := bodies.LoginBody{
		Email:    ctx.FormValue("email"),
		Password: ctx.FormValue("password"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &loginBody); err != nil {
		valErr := validationErrorException(exceptions.ValidationResponseLocationBody, err)
		loginHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIATAuthReRender(
			ctx.Context(),
			services.AppsOAuthDynamicRegistrationIATAuthReRenderOptions{
				AccountID: accountID,
				Hostname:  hostname,
				RequestID: requestID,
				Errors: utils.MapSlice(valErr.Fields, func(t *exceptions.FieldError) string {
					return fmt.Sprintf("%s %s", t.Param, t.Message)
				}),
				CSRFToken:           hiddenFields.CSRFToken,
				ACCClientID:         uPrms.ACCClientID,
				State:               hiddenFields.State,
				Domain:              hiddenFields.ClientID,
				CodeChallenge:       hiddenFields.CodeChallenge,
				CodeChallengeMethod: hiddenFields.CodeChallengeMethod,
				RedirectURI:         hiddenFields.RedirectURI,
			},
		)
		if serviceErr != nil {
			return serviceErrorHTMLResponse(logger, ctx, serviceErr)
		}

		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.
			Status(fiber.StatusOK).
			Type("html").
			SendString(loginHTML)
	}

	redirectURL, sessionKey, loggedIn, serviceErr := c.services.AppsOAuthDynamicRegistrationIATLogin(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATLoginOptions{
			AccountID:           accountID,
			Hostname:            hostname,
			RequestID:           requestID,
			ACCClientID:         uPrms.ACCClientID,
			Domain:              hiddenFields.ClientID,
			CSRFToken:           hiddenFields.CSRFToken,
			CodeChallenge:       hiddenFields.CodeChallenge,
			CodeChallengeMethod: hiddenFields.CodeChallengeMethod,
			State:               hiddenFields.State,
			RedirectURI:         hiddenFields.RedirectURI,
			Email:               loginBody.Email,
			Password:            loginBody.Password,
			BackendDomain:       c.backendDomain,
		},
	)
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeUnauthorized {
			loginHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIATAuthReRender(
				ctx.Context(),
				services.AppsOAuthDynamicRegistrationIATAuthReRenderOptions{
					AccountID:           accountID,
					Hostname:            hostname,
					RequestID:           requestID,
					Errors:              []string{"Invalid credentials"},
					CSRFToken:           hiddenFields.CSRFToken,
					ACCClientID:         uPrms.ACCClientID,
					State:               hiddenFields.State,
					Domain:              hiddenFields.ClientID,
					CodeChallenge:       hiddenFields.CodeChallenge,
					CodeChallengeMethod: hiddenFields.CodeChallengeMethod,
					RedirectURI:         hiddenFields.RedirectURI,
				},
			)
			if serviceErr != nil {
				return serviceErrorHTMLResponse(logger, ctx, serviceErr)
			}

			logResponse(logger, ctx, fiber.StatusOK)
			return ctx.
				Status(fiber.StatusOK).
				Type("html").
				SendString(loginHTML)
		}

		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	if !loggedIn {
		c.saveAppIAT2FACookie(ctx, sessionKey)
		logResponse(logger, ctx, fiber.StatusSeeOther)
		return ctx.Redirect().Status(fiber.StatusSeeOther).To(redirectURL)
	}

	c.saveAppIATCookie(ctx, sessionKey)
	logResponse(logger, ctx, fiber.StatusSeeOther)
	return ctx.Redirect().Status(fiber.StatusSeeOther).To(appsIATResumeURL(hiddenFields))
}

func (c *Controllers) AppsOAuthDynamicRegistrationIAT2FAGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIAT2FAGet")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	baseQPrms := params.OAuthDynamicRegistrationIATAuthBaseQueryParams{
		ClientID:    ctx.Query("client_id"),
		RedirectURI: ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), baseQPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ResponseType:    ctx.Query("response_type"),
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           ctx.Query("state"),
	}
	if err := c.validate.StructCtx(ctx.Context(), qPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	sessionID := ctx.Cookies(c.cookieName + appsIAT2FACookieSuffix)
	if sessionID == "" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	twoFAHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIAT2FARender(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIAT2FARenderOptions{
			AccountID:       accountID,
			Hostname:        hostname,
			RequestID:       requestID,
			Domain:          baseQPrms.ClientID,
			ACCClientID:     uPrms.ACCClientID,
			SessionID:       sessionID,
			Challenge:       qPrms.Challenge,
			ChallengeMethod: qPrms.ChallengeMethod,
			State:           qPrms.State,
			RedirectURI:     baseQPrms.RedirectURI,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).Type("html").SendString(twoFAHTML)
}

func (c *Controllers) AppsOAuthDynamicRegistrationIAT2FAPost(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIAT2FAPost")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	sessionID := ctx.Cookies(c.cookieName + appsIAT2FACookieSuffix)
	if sessionID == "" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnsupportedMediaTypeError("Only application/x-www-form-urlencoded is supported"))
	}

	hiddenFields := bodies.OAuthDynamicRegistrationIATAuthHiddenFieldsBody{
		CSRFToken:           ctx.FormValue("csrf_token"),
		ClientID:            ctx.FormValue("client_id"),
		ResponseType:        ctx.FormValue("response_type"),
		CodeChallenge:       ctx.FormValue("code_challenge"),
		CodeChallengeMethod: ctx.FormValue("code_challenge_method"),
		State:               ctx.FormValue("state"),
		RedirectURI:         ctx.FormValue("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &hiddenFields); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	twoFABody := bodies.TwoFactorLoginBody{
		Code: ctx.FormValue("code"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &twoFABody); err != nil {
		valErr := validationErrorException(exceptions.ValidationResponseLocationBody, err)
		twoFAHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIAT2FAReRender(
			ctx.Context(),
			services.AppsOAuthDynamicRegistrationIAT2FAReRenderOptions{
				AccountID:   accountID,
				Hostname:    hostname,
				RequestID:   requestID,
				Domain:      hiddenFields.ClientID,
				ACCClientID: uPrms.ACCClientID,
				SessionID:   sessionID,
				Errors: utils.MapSlice(valErr.Fields, func(t *exceptions.FieldError) string {
					return fmt.Sprintf("%s %s", t.Param, t.Message)
				}),
				CSRFToken:       hiddenFields.CSRFToken,
				Challenge:       hiddenFields.CodeChallenge,
				ChallengeMethod: hiddenFields.CodeChallengeMethod,
				State:           hiddenFields.State,
				RedirectURI:     hiddenFields.RedirectURI,
			},
		)
		if serviceErr != nil {
			return serviceErrorHTMLResponse(logger, ctx, serviceErr)
		}

		logResponse(logger, ctx, fiber.StatusOK)
		return ctx.
			Status(fiber.StatusOK).
			Type("html").
			SendString(twoFAHTML)
	}

	_, sessionKey, serviceErr := c.services.AppsOAuthDynamicRegistrationIATVerify2FACode(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATVerify2FACodeOptions{
			AccountID:     accountID,
			Hostname:      hostname,
			RequestID:     requestID,
			ACCClientID:   uPrms.ACCClientID,
			Domain:        hiddenFields.ClientID,
			SessionID:     sessionID,
			CSRFToken:     hiddenFields.CSRFToken,
			Code:          twoFABody.Code,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeUnauthorized {
			twoFAHTML, serviceErr := c.services.AppsOAuthDynamicRegistrationIAT2FAReRender(
				ctx.Context(),
				services.AppsOAuthDynamicRegistrationIAT2FAReRenderOptions{
					AccountID:       accountID,
					Hostname:        hostname,
					RequestID:       requestID,
					Domain:          hiddenFields.ClientID,
					ACCClientID:     uPrms.ACCClientID,
					SessionID:       sessionID,
					Errors:          []string{"Invalid 2FA code"},
					CSRFToken:       hiddenFields.CSRFToken,
					Challenge:       hiddenFields.CodeChallenge,
					ChallengeMethod: hiddenFields.CodeChallengeMethod,
					State:           hiddenFields.State,
					RedirectURI:     hiddenFields.RedirectURI,
				},
			)
			if serviceErr != nil {
				return serviceErrorHTMLResponse(logger, ctx, serviceErr)
			}

			logResponse(logger, ctx, fiber.StatusOK)
			return ctx.
				Status(fiber.StatusOK).
				Type("html").
				SendString(twoFAHTML)
		}

		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	c.removeAppIAT2FACookie(ctx)
	c.saveAppIATCookie(ctx, sessionKey)
	logResponse(logger, ctx, fiber.StatusSeeOther)
	return ctx.Redirect().Status(fiber.StatusSeeOther).To(appsIATResumeURL(hiddenFields))
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATExtAuthGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATExtAuthGet")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := struct {
		ACCClientID string `validate:"required,min=22,max=22,alphanum"`
		Provider    string `validate:"required,oneof=apple facebook github google microsoft"`
	}{
		ACCClientID: ctx.Params("accClientID"),
		Provider:    ctx.Params("provider"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	baseQPrms := params.OAuthDynamicRegistrationIATAuthBaseQueryParams{
		ClientID:    ctx.Query("client_id"),
		RedirectURI: ctx.Query("redirect_uri"),
	}
	if err := c.validate.StructCtx(ctx.Context(), baseQPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	responseType := ctx.Query("response_type")
	state := ctx.Query("state")
	if responseType != "code" {
		return c.redirectErrorCallback(logger, ctx, baseQPrms.RedirectURI, state, exceptions.OAuthErrorUnsupportedResponseType)
	}

	qPrms := params.OAuthDynamicRegistrationIATAuthQueryParams{
		ResponseType:    responseType,
		Challenge:       ctx.Query("code_challenge"),
		ChallengeMethod: ctx.Query("code_challenge_method"),
		State:           state,
	}
	if err := c.validate.StructCtx(ctx.Context(), qPrms); err != nil {
		return c.redirectErrorCallback(logger, ctx, baseQPrms.RedirectURI, state, exceptions.OAuthErrorInvalidRequest)
	}

	authURL, serviceErr := c.services.AppsOAuthDynamicRegistrationIATExtGet(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATExtGetOptions{
			AccountID:     accountID,
			Hostname:      hostname,
			RequestID:     requestID,
			ACCClientID:   uPrms.ACCClientID,
			Provider:      uPrms.Provider,
			Domain:        baseQPrms.ClientID,
			CallbackURL:   "https://" + hostname + paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken + "/" + uPrms.ACCClientID + paths.InitialAccessTokenAuthEXT + "/" + uPrms.Provider + paths.InitialAccessTokenCallback,
			RedirectURI:   baseQPrms.RedirectURI,
			State:         qPrms.State,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(authURL)
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATExtCB(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATExtCB")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATExtAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
		Provider:    ctx.Params("provider"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	qPrms := params.OAuthCallbackQueryParams{
		Code:  ctx.Query("code"),
		State: ctx.Query("state"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &qPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	cbURL, serviceErr := c.services.AppsOAuthDynamicRegistrationIATExtCB(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATExtCBOptions{
			AccountID:     accountID,
			Hostname:      hostname,
			RequestID:     requestID,
			ACCClientID:   uPrms.ACCClientID,
			Provider:      uPrms.Provider,
			State:         qPrms.State,
			Code:          qPrms.Code,
			RedirectURL:   "https://" + hostname + paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken + "/" + uPrms.ACCClientID + paths.InitialAccessTokenAuthEXT + "/" + uPrms.Provider + paths.InitialAccessTokenCallback,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(cbURL)
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATExtAppleCB(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATExtAppleCB")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, hostErr)
	}
	hostname := username + "." + c.backendDomain

	uPrms := params.OAuthDynamicRegistrationIATExtAppleURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnsupportedMediaTypeError("Only application/x-www-form-urlencoded is supported"))
	}

	qPrms := bodies.OAuthDynamicRegistrationIATExtAppleBody{
		Code:  ctx.FormValue("code"),
		State: ctx.FormValue("state"),
		User:  ctx.FormValue("user"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &qPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	user := new(bodies.OAuthDynamicRegistrationIATExtAppleUserBody)
	if err := json.Unmarshal([]byte(qPrms.User), user); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}
	if err := c.validate.StructCtx(ctx.Context(), user); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewForbiddenError())
	}

	cbURL, serviceErr := c.services.AppsOAuthDynamicRegistrationIATExtAppleCB(
		ctx.Context(),
		services.AppsOAuthDynamicRegistrationIATExtAppleCBOptions{
			AccountID:     accountID,
			Hostname:      hostname,
			RequestID:     requestID,
			ACCClientID:   uPrms.ACCClientID,
			Email:         user.Email,
			Code:          qPrms.Code,
			State:         qPrms.State,
			RedirectURL:   "https://" + hostname + paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken + "/" + uPrms.ACCClientID + paths.InitialAccessTokenAuthEXT + "/" + services.AuthProviderApple + paths.InitialAccessTokenCallback,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(cbURL)
}

func (c *Controllers) AppsOAuthDynamicRegistrationIATToken(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthAppsDynamicRegistrationIAT, "AppsOAuthDynamicRegistrationIATToken")
	logRequest(logger, ctx)

	username, accountID, hostErr := getHostAccount(ctx)
	if hostErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnauthorizedClient)
	}
	hostname := username + "." + c.backendDomain

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	grantType := ctx.FormValue("grant_type")
	if grantType != "authorization_code" {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorUnsupportedGrantType)
	}

	body := bodies.OAuthDynamicRegistrationIATTokenBody{
		GrantType:    grantType,
		Code:         ctx.FormValue("code"),
		ClientID:     ctx.FormValue("client_id"),
		CodeVerifier: ctx.FormValue("code_verifier"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	authDTO, serviceErr := c.services.VerifyAppsOAuthDynamicRegistrationIATCode(
		ctx.Context(),
		services.VerifyAppsOAuthDynamicRegistrationIATCodeOptions{
			AccountID:     accountID,
			Hostname:      hostname,
			BackendDomain: c.backendDomain,
			RequestID:     requestID,
			Code:          body.Code,
			CodeVerifier:  body.CodeVerifier,
			Domain:        body.ClientID,
		},
	)
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(authDTO)
}
