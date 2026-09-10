// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v3"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const oauthDynamicRegistration string = "oauth_dynamic_registration"

func (c *Controllers) OAuthDynamicRegistration(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistration")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	if !ok {
		logger.ErrorContext(ctx.Context(), "account should be set in context by middleware")
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}
	domain, ok := ctx.Locals("domain").(string)
	if !ok {
		logger.ErrorContext(ctx.Context(), "domain should be set in context by middleware")
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}

	body := new(bodies.OAuthDynamicClientRegistrationBody)
	if err := ctx.Bind().Body(body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}

	accountCredentialsDTO, serviceErr := c.services.CreateAccountCredentialsRegistration(
		ctx.Context(),
		services.CreateAccountCredentialsRegistrationOptions{
			RequestID:                    requestID,
			AccountPublicID:              accountClaims.AccountID,
			IATDomain:                    domain,
			AccountVersion:               accountClaims.AccountVersion,
			ApplicationType:              body.ApplicationType,
			RedirectURIs:                 body.RedirectURIs,
			TokenEndpointAuthMethod:      body.TokenEndpointAuthMethod,
			GrantTypes:                   body.GrantTypes,
			ResponseTypes:                body.ResponseTypes,
			ClientName:                   body.ClientName,
			ClientURI:                    body.ClientURI,
			LogoURI:                      body.LogoURI,
			TOSURI:                       body.TOSURI,
			PolicyURI:                    body.PolicyURI,
			Contacts:                     body.Contacts,
			SoftwareID:                   body.SoftwareID,
			SoftwareVersion:              body.SoftwareVersion,
			SoftwareStatement:            body.SoftwareStatement,
			JWKsURI:                      body.JWKsURI,
			JWKs:                         body.JWKs,
			FrontendDomain:               c.frontendDomain,
			BackendDomain:                c.backendDomain,
			RequireAuthTime:              body.RequireAuthTime,
			DefaultMaxAge:                body.DefaultMaxAge,
			SubjectType:                  body.SubjectType,
			IDTokenSignedResponseAlg:     body.IDTokenSignedResponseAlg,
			IDTokenEncryptedResponseAlg:  body.IDTokenEncryptedResponseAlg,
			IDTokenEncryptedResponseEnc:  body.IDTokenEncryptedResponseEnc,
			RequestObjectSigningAlg:      body.RequestObjectSigningAlg,
			RequestObjectEncryptionAlg:   body.RequestObjectEncryptionAlg,
			RequestObjectEncryptionEnc:   body.RequestObjectEncryptionEnc,
			DefaultACRValues:             body.DefaultACRValues,
			Scope:                        body.Scope,
			SectorIdentifierURI:          body.SectorIdentifierURI,
			InitiateLoginURI:             body.InitiateLoginURI,
			RequestURIs:                  body.RequestURIs,
			UserInfoSignedResponseAlg:    body.UserInfoSignedResponseAlg,
			UserInfoEncryptedResponseAlg: body.UserInfoEncryptedResponseAlg,
			UserInfoEncryptedResponseEnc: body.UserInfoEncryptedResponseEnc,
			TokenEndpointAuthSigningAlg:  body.TokenEndpointAuthSigningAlg,
			AccessTokenSigningAlg:        body.AccessTokenSigningAlg,
		},
	)
	if serviceErr != nil {
		return dynamicRegistrationServiceError(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(accountCredentialsDTO.Registration)
}

func (c *Controllers) OAuthAppDynamicRegistration(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthAppDynamicRegistration")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.OAuthDynamicClientRegistrationBody)
	if err := ctx.Bind().Body(body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}

	isAuthenticated, ok := ctx.Locals("isAuthenticated").(bool)
	if !ok {
		logger.ErrorContext(ctx.Context(), "isAuthenticated should be set in context by middleware")
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}

	domain, ok := ctx.Locals("domain").(string)
	if isAuthenticated && !ok {
		logger.ErrorContext(ctx.Context(), "domain should be set in context by middleware")
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}

	account, ok := ctx.Locals("account").(tokens.AccountClaims)
	if isAuthenticated && !ok {
		logger.ErrorContext(ctx.Context(), "account should be set in context by middleware")
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorServerError)
	}

	appDTO, serviceErr := c.services.CreateAppCredentialsRegistration(
		ctx.Context(),
		services.CreateAppCredentialsRegistrationOptions{
			RequestID:                    requestID,
			IsAuthenticated:              isAuthenticated,
			AccountID:                    accountID,
			IATDomain:                    domain,
			AccountVersion:               account.AccountVersion,
			ApplicationType:              body.ApplicationType,
			RedirectURIs:                 body.RedirectURIs,
			TokenEndpointAuthMethod:      body.TokenEndpointAuthMethod,
			GrantTypes:                   body.GrantTypes,
			ResponseTypes:                body.ResponseTypes,
			ClientName:                   body.ClientName,
			ClientURI:                    body.ClientURI,
			LogoURI:                      body.LogoURI,
			TOSURI:                       body.TOSURI,
			PolicyURI:                    body.PolicyURI,
			Contacts:                     body.Contacts,
			SoftwareID:                   body.SoftwareID,
			SoftwareVersion:              body.SoftwareVersion,
			SoftwareStatement:            body.SoftwareStatement,
			JWKsURI:                      body.JWKsURI,
			JWKs:                         body.JWKs,
			FrontendDomain:               c.frontendDomain,
			BackendDomain:                c.backendDomain,
			RequireAuthTime:              body.RequireAuthTime,
			DefaultMaxAge:                body.DefaultMaxAge,
			SubjectType:                  body.SubjectType,
			IDTokenSignedResponseAlg:     body.IDTokenSignedResponseAlg,
			IDTokenEncryptedResponseAlg:  body.IDTokenEncryptedResponseAlg,
			IDTokenEncryptedResponseEnc:  body.IDTokenEncryptedResponseEnc,
			RequestObjectSigningAlg:      body.RequestObjectSigningAlg,
			RequestObjectEncryptionAlg:   body.RequestObjectEncryptionAlg,
			RequestObjectEncryptionEnc:   body.RequestObjectEncryptionEnc,
			DefaultACRValues:             body.DefaultACRValues,
			Scope:                        body.Scope,
			SectorIdentifierURI:          body.SectorIdentifierURI,
			InitiateLoginURI:             body.InitiateLoginURI,
			RequestURIs:                  body.RequestURIs,
			UserInfoSignedResponseAlg:    body.UserInfoSignedResponseAlg,
			UserInfoEncryptedResponseAlg: body.UserInfoEncryptedResponseAlg,
			UserInfoEncryptedResponseEnc: body.UserInfoEncryptedResponseEnc,
			TokenEndpointAuthSigningAlg:  body.TokenEndpointAuthSigningAlg,
			AccessTokenSigningAlg:        body.AccessTokenSigningAlg,
		},
	)
	if serviceErr != nil {
		return dynamicRegistrationServiceError(logger, ctx, serviceErr)
	}

	logResponse(logger, ctx, fiber.StatusCreated)
	return ctx.Status(fiber.StatusCreated).JSON(appDTO.Registration)
}

func registrationClientIDFromContext(ctx fiber.Ctx) (string, bool) {
	clientID, ok := ctx.Locals("registrationClientID").(string)
	return clientID, ok && clientID != ""
}

func (c *Controllers) bindRegistrationBody(ctx fiber.Ctx) (*bodies.OAuthDynamicClientRegistrationBody, error) {
	body := new(bodies.OAuthDynamicClientRegistrationBody)
	if err := ctx.Bind().Body(body); err != nil {
		return nil, err
	}
	return body, nil
}

func (c *Controllers) OAuthDynamicRegistrationGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistrationGet")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if !ok || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}

	dto, serviceErr := c.services.GetRegisteredAccountCredentials(ctx.Context(), services.GetRegisteredClientOptions{
		RequestID: requestID, AccountPublicID: accountClaims.AccountID, ClientID: tokenClientID, BackendDomain: c.backendDomain,
	})
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dto)
}

func (c *Controllers) OAuthAppDynamicRegistrationGet(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthAppDynamicRegistrationGet")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	username, _, serviceErr := getHostAccount(ctx)
	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if serviceErr != nil || !ok || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}

	dto, serviceErr := c.services.GetRegisteredApp(ctx.Context(), services.GetRegisteredClientOptions{
		RequestID: requestID, AccountPublicID: accountClaims.AccountID, ClientID: tokenClientID,
		BackendDomain: c.backendDomain, HostUsername: username,
	})
	if serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dto)
}

func (c *Controllers) OAuthDynamicRegistrationUpdate(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistrationUpdate")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if !ok || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	body, err := c.bindRegistrationBody(ctx)
	if err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}

	dto, serviceErr := c.services.UpdateRegisteredAccountCredentials(ctx.Context(), services.UpdateRegisteredClientOptions{
		ClientID: tokenClientID,
		CreateAccountCredentialsRegistrationOptions: services.CreateAccountCredentialsRegistrationOptions{
			RequestID: requestID, AccountPublicID: accountClaims.AccountID, AccountVersion: accountClaims.AccountVersion,
			ApplicationType: body.ApplicationType, RedirectURIs: body.RedirectURIs, TokenEndpointAuthMethod: body.TokenEndpointAuthMethod,
			GrantTypes: body.GrantTypes, ResponseTypes: body.ResponseTypes, ClientName: body.ClientName, ClientURI: body.ClientURI,
			LogoURI: body.LogoURI, TOSURI: body.TOSURI, PolicyURI: body.PolicyURI, Contacts: body.Contacts, SoftwareID: body.SoftwareID,
			SoftwareVersion: body.SoftwareVersion, SoftwareStatement: body.SoftwareStatement, JWKsURI: body.JWKsURI, JWKs: body.JWKs,
			FrontendDomain: c.frontendDomain, BackendDomain: c.backendDomain, RequireAuthTime: body.RequireAuthTime,
			DefaultMaxAge: body.DefaultMaxAge, SubjectType: body.SubjectType, IDTokenSignedResponseAlg: body.IDTokenSignedResponseAlg,
			IDTokenEncryptedResponseAlg: body.IDTokenEncryptedResponseAlg, IDTokenEncryptedResponseEnc: body.IDTokenEncryptedResponseEnc,
			RequestObjectSigningAlg: body.RequestObjectSigningAlg, RequestObjectEncryptionAlg: body.RequestObjectEncryptionAlg,
			RequestObjectEncryptionEnc: body.RequestObjectEncryptionEnc, DefaultACRValues: body.DefaultACRValues, Scope: body.Scope,
			SectorIdentifierURI: body.SectorIdentifierURI, InitiateLoginURI: body.InitiateLoginURI, RequestURIs: body.RequestURIs,
			UserInfoSignedResponseAlg: body.UserInfoSignedResponseAlg, UserInfoEncryptedResponseAlg: body.UserInfoEncryptedResponseAlg,
			UserInfoEncryptedResponseEnc: body.UserInfoEncryptedResponseEnc, TokenEndpointAuthSigningAlg: body.TokenEndpointAuthSigningAlg,
			AccessTokenSigningAlg: body.AccessTokenSigningAlg,
		},
	})
	if serviceErr != nil {
		return dynamicRegistrationServiceError(logger, ctx, serviceErr)
	}
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dto)
}

func (c *Controllers) OAuthAppDynamicRegistrationUpdate(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthAppDynamicRegistrationUpdate")
	logRequest(logger, ctx)
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	username, accountID, serviceErr := getHostAccount(ctx)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if serviceErr != nil || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	body, err := c.bindRegistrationBody(ctx)
	if err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}

	dto, serviceErr := c.services.UpdateRegisteredApp(ctx.Context(), services.UpdateRegisteredAppOptions{
		ClientID: tokenClientID, HostUsername: username,
		CreateAppCredentialsRegistrationOptions: services.CreateAppCredentialsRegistrationOptions{
			RequestID: requestID, AccountID: accountID, ApplicationType: body.ApplicationType, RedirectURIs: body.RedirectURIs,
			TokenEndpointAuthMethod: body.TokenEndpointAuthMethod, GrantTypes: body.GrantTypes, ResponseTypes: body.ResponseTypes,
			ClientName: body.ClientName, ClientURI: body.ClientURI, LogoURI: body.LogoURI, TOSURI: body.TOSURI, PolicyURI: body.PolicyURI,
			Contacts: body.Contacts, SoftwareID: body.SoftwareID, SoftwareVersion: body.SoftwareVersion, SoftwareStatement: body.SoftwareStatement,
			JWKsURI: body.JWKsURI, JWKs: body.JWKs, FrontendDomain: c.frontendDomain, BackendDomain: c.backendDomain,
			RequireAuthTime: body.RequireAuthTime, DefaultMaxAge: body.DefaultMaxAge, SubjectType: body.SubjectType,
			IDTokenSignedResponseAlg: body.IDTokenSignedResponseAlg, IDTokenEncryptedResponseAlg: body.IDTokenEncryptedResponseAlg,
			IDTokenEncryptedResponseEnc: body.IDTokenEncryptedResponseEnc, RequestObjectSigningAlg: body.RequestObjectSigningAlg,
			RequestObjectEncryptionAlg: body.RequestObjectEncryptionAlg, RequestObjectEncryptionEnc: body.RequestObjectEncryptionEnc,
			DefaultACRValues: body.DefaultACRValues, Scope: body.Scope, SectorIdentifierURI: body.SectorIdentifierURI,
			InitiateLoginURI: body.InitiateLoginURI, RequestURIs: body.RequestURIs, UserInfoSignedResponseAlg: body.UserInfoSignedResponseAlg,
			UserInfoEncryptedResponseAlg: body.UserInfoEncryptedResponseAlg, UserInfoEncryptedResponseEnc: body.UserInfoEncryptedResponseEnc,
			TokenEndpointAuthSigningAlg: body.TokenEndpointAuthSigningAlg, AccessTokenSigningAlg: body.AccessTokenSigningAlg,
		},
	})
	if serviceErr != nil {
		return dynamicRegistrationServiceError(logger, ctx, serviceErr)
	}
	logResponse(logger, ctx, fiber.StatusOK)
	return ctx.Status(fiber.StatusOK).JSON(dto)
}

func (c *Controllers) OAuthDynamicRegistrationDelete(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistrationDelete")
	logRequest(logger, ctx)

	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if !ok || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	if serviceErr := c.services.DeleteRegisteredAccountCredentials(ctx.Context(), services.GetRegisteredClientOptions{
		RequestID: requestID, AccountPublicID: accountClaims.AccountID, ClientID: tokenClientID,
	}); serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}

func (c *Controllers) OAuthAppDynamicRegistrationDelete(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthAppDynamicRegistrationDelete")
	logRequest(logger, ctx)

	_, _, serviceErr := getHostAccount(ctx)
	accountClaims, ok := ctx.Locals("account").(tokens.AccountClaims)
	tokenClientID, tokenOK := registrationClientIDFromContext(ctx)
	if serviceErr != nil || !ok || !tokenOK || tokenClientID != ctx.Params("clientID") {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	if serviceErr := c.services.DeleteRegisteredApp(ctx.Context(), services.GetRegisteredClientOptions{
		RequestID: requestID, AccountPublicID: accountClaims.AccountID, ClientID: tokenClientID,
	}); serviceErr != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidToken)
	}
	logResponse(logger, ctx, fiber.StatusNoContent)
	return ctx.SendStatus(fiber.StatusNoContent)
}
