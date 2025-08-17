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
	router := v1PathRouter(app).Group(
		paths.AccountsBase+paths.CredentialsBase+paths.DynamicRegistrationBase,
		r.controllers.AccountAccessClaimsMiddleware,
	)

	credentialsConfigsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsConfigsWrite)
	credentialsConfigsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsConfigsRead)

	// Dynamic Registration Config
	router.Get(
		paths.Config,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountDynamicRegistrationConfig,
	)
	router.Put(
		paths.Config,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.UpsertAccountDynamicRegistrationConfig,
	)
	router.Delete(
		paths.Config,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountDynamicRegistrationConfig,
	)

	// Dynamic Registration Domains
	router.Post(
		paths.Domains,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.CreateAccountCredentialsRegistrationDomain,
	)
	router.Get(
		paths.Domains,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.ListAccountCredentialsRegistrationDomains,
	)
	router.Get(
		paths.Domains+paths.SingleDomain,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsRegistrationDomain,
	)
	router.Delete(
		paths.Domains+paths.SingleDomain,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentialsRegistrationDomain,
	)
	router.Post(
		paths.Domains+paths.VerifyDomain,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.VerifyAccountCredentialsRegistrationDomain,
	)
	// Dynamic Registration Domains Code
	router.Get(
		paths.Domains+paths.DomainCode,
		credentialsConfigsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsRegistrationDomainCode,
	)
	router.Put(
		paths.Domains+paths.DomainCode,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.UpsertAccountCredentialsRegistrationDomainCode,
	)
	router.Delete(
		paths.Domains+paths.DomainCode,
		credentialsConfigsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentialsRegistrationDomainCode,
	)
}
