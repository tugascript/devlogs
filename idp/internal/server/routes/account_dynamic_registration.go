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

func (r *Routes) AccountDynamicRegistrationRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(
		paths.AccountsBase+paths.CredentialsBase+paths.DynamicRegistrationBase,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
	)

	credentialsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsWrite)
	credentialsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsRead)

	router.Get(
		paths.Config,
		credentialsReadScopeMiddleware,
		r.controllers.GetAccountDynamicRegistrationConfig,
	)
	router.Put(
		paths.Config,
		credentialsWriteScopeMiddleware,
		r.controllers.UpsertAccountDynamicRegistrationConfig,
	)
}
