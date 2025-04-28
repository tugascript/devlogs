// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AccountCredentialsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountCredentialsBase, r.controllers.AccountAccessClaimsMiddleware)

	router.Post(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.CreateAccountCredentials)
	router.Get(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.ListAccountCredentials)
	router.Get(
		paths.AccountCredentialsSingle,
		r.controllers.AdminScopeMiddleware,
		r.controllers.GetSingleAccountCredentials,
	)
	router.Put(
		paths.AccountCredentialsSingle,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountCredentials,
	)
	router.Delete(
		paths.AccountCredentialsSingle,
		r.controllers.AdminScopeMiddleware,
		r.controllers.DeleteAccountCredentials,
	)
	router.Patch(
		paths.AccountCredentialsRefreshSecret,
		r.controllers.AdminScopeMiddleware,
		r.controllers.RefreshAccountCredentialsSecret,
	)
}
