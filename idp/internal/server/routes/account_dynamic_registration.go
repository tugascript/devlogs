// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

func (r *Routes) AccountDynamicRegistrationConfigurationRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase + paths.CredentialsBase + paths.DynamicRegistrationBase)

	credentialsConfigsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsConfigsWrite)
	credentialsConfigsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsConfigsRead)

	// Dynamic Registration Config
	configRouter := router.Group(paths.Config, r.controllers.AccountAccessClaimsMiddleware)
	configRouter.Get(
		paths.Base,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountDynamicRegistrationConfig,
	)
	configRouter.Put(
		paths.Base,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.UpsertAccountDynamicRegistrationConfig,
	)
	configRouter.Delete(
		paths.Base,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountDynamicRegistrationConfig,
	)

	// Dynamic Registration Domains
	domainsRouter := router.Group(paths.Domains, r.controllers.AccountAccessClaimsMiddleware)
	domainsRouter.Post(
		paths.Base,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.CreateAccountCredentialsRegistrationDomain,
	)
	domainsRouter.Get(
		paths.Base,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.ListAccountCredentialsRegistrationDomains,
	)
	domainsRouter.Get(
		paths.SingleDomain,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsRegistrationDomain,
	)
	domainsRouter.Delete(
		paths.SingleDomain,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentialsRegistrationDomain,
	)
	domainsRouter.Post(
		paths.VerifyDomain,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.VerifyAccountCredentialsRegistrationDomain,
	)
	// Dynamic Registration Domains Code
	domainsRouter.Get(
		paths.DomainCode,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsRegistrationDomainCode,
	)
	domainsRouter.Put(
		paths.DomainCode,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.UpsertAccountCredentialsRegistrationDomainCode,
	)
	domainsRouter.Delete(
		paths.DomainCode,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentialsRegistrationDomainCode,
	)

	// Initial Access Token (IAT) routes
	iatRouter := router.Group(paths.InitialAccessToken)

	// Dynamic Registration IAT Code Exchange flow
	iatRouter.Get(paths.OAuthAuth, r.controllers.OAuthDynamicRegistrationIATAuth)
	const loginRoute = paths.InitialAccessTokenSingle + paths.AuthLogin
	iatRouter.Get(loginRoute, r.controllers.OAuthDynamicRegistrationIATLoginGet)
	iatRouter.Post(loginRoute, r.controllers.OAuthDynamicRegistrationIATLoginPost)
	iatRouter.Get(loginRoute+paths.Auth2FA, r.controllers.OAuthDynamicRegistrationIAT2FAGet)
	iatRouter.Post(loginRoute+paths.Auth2FA, r.controllers.OAuthDynamicRegistrationIAT2FAPost)
	iatRouter.Post(paths.OAuthToken, r.controllers.OAuthDynamicRegistrationIATToken)

}
