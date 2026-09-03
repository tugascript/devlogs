// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/gofiber/fiber/v3"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthDynamicRegistrationIAT string = "oauth_dynamic_registration_iat"

	accountsIATCookieSuffix    string = "_acc_iat"
	accountsIAT2FACookieSuffix string = "_acc_iat_2fa"
)

func (c *Controllers) OAuthDynamicRegistrationIATAuth(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATAuth")
	logRequest(logger, ctx)

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

	sessionKey := ctx.Cookies(c.cookieName + accountsIATCookieSuffix)
	if sessionKey != "" {
		// This ensures that the key is only used once
		c.removeAccountIATCookie(ctx)
	}

	redirectURL, serviceErr := c.services.InitiateOAuthDynamicRegistrationIATAuth(
		ctx.Context(),
		services.InitiateOAuthDynamicRegistrationIATAuthOptions{
			RequestID:       requestID,
			Domain:          baseQPrms.ClientID,
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

func (c *Controllers) OAuthDynamicRegistrationIATLoginGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATLoginGet")
	logRequest(logger, ctx)

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

	loginHTML, serviceErr := c.services.OAuthDynamicRegistrationIATAuthRender(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATAuthRenderOptions{
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

func (c *Controllers) saveAccountIATCookie(
	ctx fiber.Ctx,
	sessionKey string,
) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + accountsIATCookieSuffix,
		Value:    sessionKey,
		Path:     paths.V1 + paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken + paths.OAuthAuth,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.GetOAuthCodeTTL()),
	})
}

func (c *Controllers) removeAccountIATCookie(ctx fiber.Ctx) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + accountsIATCookieSuffix,
		Value:    "",
		Path:     paths.V1 + paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken + paths.OAuthAuth,
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteNoneMode,
		MaxAge:   -1,
	})
}

func (c *Controllers) saveAccountIAT2FACookie(ctx fiber.Ctx, sessionID, clientID string) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + accountsIAT2FACookieSuffix,
		Value:    sessionID,
		Path:     paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken + "/" + clientID + paths.OAuthAuth,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   int(c.services.GetOAuthCodeTTL()),
	})
}

func (c *Controllers) removeAccountIAT2FACookie(ctx fiber.Ctx, clientID string) {
	ctx.Cookie(&fiber.Cookie{
		Name:     c.cookieName + accountsIAT2FACookieSuffix,
		Value:    "",
		Path:     paths.AccountsBase + paths.CredentialsBase + paths.InitialAccessToken + "/" + clientID + paths.OAuthAuth,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
		Secure:   true,
		MaxAge:   -1,
	})
}

func (c *Controllers) OAuthDynamicRegistrationIATLoginPost(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATLoginPost")
	logRequest(logger, ctx)

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
		loginHTML, serviceErr := c.services.OAuthDynamicRegistrationIATAuthReRender(
			ctx.Context(),
			services.OAuthDynamicRegistrationIATAuthReRenderOptions{
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

	redirectURL, sessionKey, loggedIn, serviceErr := c.services.OAuthDynamicRegistrationIATLogin(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATLoginOptions{
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
			loginHTML, serviceErr := c.services.OAuthDynamicRegistrationIATAuthReRender(
				ctx.Context(),
				services.OAuthDynamicRegistrationIATAuthReRenderOptions{
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

	if loggedIn {
		c.saveAccountIAT2FACookie(ctx, sessionKey, uPrms.ACCClientID)
		logResponse(logger, ctx, fiber.StatusSeeOther)
		return ctx.Redirect().Status(fiber.StatusSeeOther).To(redirectURL)
	}

	c.saveAccountIATCookie(ctx, sessionKey)
	logResponse(logger, ctx, fiber.StatusSeeOther)
	return ctx.Redirect().Status(fiber.StatusSeeOther).To(redirectURL)
}

func (c *Controllers) OAuthDynamicRegistrationIAT2FAGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIAT2FAGet")
	logRequest(logger, ctx)

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

	sessionID := ctx.Cookies(c.cookieName + accountsIAT2FACookieSuffix)
	if sessionID == "" {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewUnauthorizedError())
	}

	twoFAHTML, serviceErr := c.services.OAuthDynamicRegistrationIAT2FARender(
		ctx.Context(),
		services.OAuthDynamicRegistrationIAT2FARenderOptions{
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

func (c *Controllers) OAuthDynamicRegistrationIAT2FAPost(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIAT2FAPost")
	logRequest(logger, ctx)

	uPrms := params.OAuthDynamicRegistrationIATAuthURLParams{
		ACCClientID: ctx.Params("accClientID"),
	}
	if err := c.validate.StructCtx(ctx.Context(), &uPrms); err != nil {
		return serviceErrorHTMLResponse(logger, ctx, exceptions.NewNotFoundError())
	}

	sessionID := ctx.Cookies(c.cookieName + accountsIAT2FACookieSuffix)
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
		twoFAHTML, serviceErr := c.services.OAuthDynamicRegistrationIAT2FAReRender(
			ctx.Context(),
			services.OAuthDynamicRegistrationIAT2FAReRenderOptions{
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

	redirectURL, sessionKey, serviceErr := c.services.OAuthDynamicRegistrationIATVerify2FACode(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATVerify2FACodeOptions{
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
			twoFAHTML, serviceErr := c.services.OAuthDynamicRegistrationIAT2FAReRender(
				ctx.Context(),
				services.OAuthDynamicRegistrationIAT2FAReRenderOptions{
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

	c.removeAccountIAT2FACookie(ctx, uPrms.ACCClientID)
	c.saveAccountIATCookie(ctx, sessionKey)
	logResponse(logger, ctx, fiber.StatusSeeOther)
	return ctx.Redirect().Status(fiber.StatusSeeOther).To(redirectURL)
}

func (c *Controllers) OAuthDynamicRegistrationIATExtAuthGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATExtAuthGet")
	logRequest(logger, ctx)

	uPrms := params.OAuthDynamicRegistrationIATExtAuthURLParams{
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

	authURL, serviceErr := c.services.OAuthDynamicRegistrationIATExtGet(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATExtGetOptions{
			RequestID:     requestID,
			ACCClientID:   uPrms.ACCClientID,
			Provider:      uPrms.Provider,
			Domain:        baseQPrms.ClientID,
			CallbackURL:   baseQPrms.RedirectURI,
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

func (c *Controllers) OAuthDynamicRegistrationIATExtCB(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATExtCB")
	logRequest(logger, ctx)

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

	cbURL, serviceErr := c.services.OAuthDynamicRegistrationIATExtCB(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATExtCBOptions{
			RequestID:   requestID,
			ACCClientID: uPrms.ACCClientID,
			Provider:    uPrms.Provider,
			State:       qPrms.State,
			Code:        qPrms.Code,
			RedirectURL: "https://" + c.backendDomain + paths.V1 + paths.AccountsBase +
				paths.CredentialsBase + paths.DynamicRegistrationBase + paths.InitialAccessToken +
				"/" + uPrms.ACCClientID + paths.OAuthAuth + paths.InitialAccessTokenAuthEXT + "/" +
				uPrms.Provider + paths.InitialAccessTokenCallback,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(cbURL)
}

func (c *Controllers) OAuthDynamicRegistrationIATExtAppleCB(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATExtAppleCB")
	logRequest(logger, ctx)

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

	cbURL, serviceErr := c.services.OAuthDynamicRegistrationIATExtAppleCB(
		ctx.Context(),
		services.OAuthDynamicRegistrationIATExtAppleCBOptions{
			RequestID:   requestID,
			ACCClientID: uPrms.ACCClientID,
			Email:       user.Email,
			Code:        qPrms.Code,
			State:       qPrms.State,
			RedirectURL: "https://" + c.backendDomain + paths.V1 + paths.AccountsBase +
				paths.CredentialsBase + paths.DynamicRegistrationBase + paths.InitialAccessToken +
				"/" + uPrms.ACCClientID + paths.OAuthAuth + paths.InitialAccessTokenAuthEXT + "/" +
				services.AuthProviderApple + paths.InitialAccessTokenCallback,
			BackendDomain: c.backendDomain,
		},
	)
	if serviceErr != nil {
		return serviceErrorHTMLResponse(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusFound)
	return ctx.Redirect().Status(fiber.StatusFound).To(cbURL)
}

func (c *Controllers) OAuthDynamicRegistrationIATToken(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistrationIAT, "OAuthDynamicRegistrationIATToken")
	logRequest(logger, ctx)

	if ctx.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	grantType := ctx.Get("grant_type")
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

	authDTO, serviceErr := c.services.VerifyOAuthDynamicRegistrationIATCode(
		ctx.Context(),
		services.VerifyOAuthDynamicRegistrationIATCodeOptions{
			RequestID:    requestID,
			Code:         body.Code,
			CodeVerifier: body.CodeVerifier,
			Domain:       body.ClientID,
		},
	)
	if serviceErr != nil {
		return oauthErrorResponseMapper(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(authDTO)
}
