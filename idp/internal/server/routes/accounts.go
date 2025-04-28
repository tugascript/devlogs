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

func (r *Routes) AccountsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase, r.controllers.AccountAccessClaimsMiddleware)

	router.Get(paths.AccountMe, r.controllers.GetCurrentAccount)
	router.Delete(paths.AccountMe, r.controllers.AdminScopeMiddleware, r.controllers.DeleteAccount)
	router.Delete(paths.AccountMeConfirm, r.controllers.AdminScopeMiddleware, r.controllers.ConfirmDeleteAccount)
	router.Patch(paths.AccountPassword, r.controllers.AdminScopeMiddleware, r.controllers.UpdateAccountPassword)
	router.Patch(
		paths.AccountPasswordConfirm,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ConfirmUpdateAccountPassword,
	)
	router.Patch(
		paths.AccountEmail,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountEmail,
	)
	router.Patch(
		paths.AccountEmailConfirm,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ConfirmUpdateAccountEmail,
	)
}
