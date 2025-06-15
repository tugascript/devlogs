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
	router := v1PathRouter(app).Group(paths.AccountsBase)

	router.Get(paths.AccountMe, r.controllers.AccountAccessClaimsMiddleware, r.controllers.GetCurrentAccount)
	router.Put(
		paths.AccountMe,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccount,
	)
	router.Delete(
		paths.AccountMe,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.DeleteAccount,
	)
	router.Post(
		paths.AccountMe+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmDeleteAccount,
	)
	router.Post(
		paths.AccountPassword,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.CreateAccountPassword,
	)
	router.Patch(
		paths.AccountPassword,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountPassword,
	)
	router.Post(
		paths.AccountPassword+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmUpdateAccountPassword,
	)
	router.Patch(
		paths.AccountEmail,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountEmail,
	)
	router.Post(
		paths.AccountEmail+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmUpdateAccountEmail,
	)
	router.Patch(
		paths.TwoFA,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccount2FA,
	)
	router.Post(
		paths.TwoFA+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmUpdateAccount2FA,
	)
	router.Patch(
		paths.AccountUsername,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountUsername,
	)
	router.Post(
		paths.AccountUsername+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmUpdateAccountUsername,
	)
}
