// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"github.com/gofiber/fiber/v3"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/params"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
)

const oauthDynamicRegistration string = "oauth_dynamic_registration"

func (c *Controllers) OAuthDynamicRegistration(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthDynamicRegistration")
	logRequest(logger, ctx)

	urlParams := params.AccountURLParams{AccountPublicID: ctx.Params("accountPublicID")}
	if err := c.validate.StructCtx(ctx.Context(), &urlParams); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	accountPublicID, err := uuid.Parse(urlParams.AccountPublicID)
	if err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidRequest)
	}

	body := new(bodies.OAuthDynamicClientRegistrationBody)
	if err := ctx.Bind().Body(body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}
	if err := c.validate.StructCtx(ctx.Context(), body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}
	if body.JWKs != nil && body.JWKsURI != "" {
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

	accountCredentialsDTO, serviceErr := c.services.CreateAccountCredentialsRegistration(
		ctx.Context(),
		services.CreateAccountCredentialsRegistrationOptions{
			RequestID:                    requestID,
			AccountPublicID:              accountPublicID,
			IsAuthenticated:              isAuthenticated,
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
	return ctx.Status(fiber.StatusCreated).JSON(&accountCredentialsDTO)
}

func (c *Controllers) OAuthAppDynamicRegistration(ctx fiber.Ctx) error {
	requestID := getRequestID(ctx)
	logger := c.buildLogger(requestID, oauthDynamicRegistration, "OAuthAppDynamicRegistration")
	logRequest(logger, ctx)

	_, accountID, serviceErr := getHostAccount(ctx)
	if serviceErr != nil {
		return serviceErrorResponse(logger, ctx, serviceErr)
	}

	body := new(bodies.OAuthDynamicClientRegistrationBody)
	if err := ctx.Bind().Body(body); err != nil {
		return oauthErrorResponse(logger, ctx, exceptions.OAuthErrorInvalidClientMetadata)
	}
	if err := c.validate.StructCtx(ctx.Context(), body); err != nil {
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
	return ctx.Status(fiber.StatusCreated).JSON(&appDTO)
}
