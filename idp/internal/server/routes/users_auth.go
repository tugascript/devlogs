// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services"
)

func (r *Routes) UsersAuthRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AppsBase+paths.UsersBase, r.controllers.AccountHostMiddleware)

	router.Post(paths.AuthRegister, r.controllers.AppAccessClaimsMiddleware, r.controllers.RegisterUser)
	router.Post(paths.AuthConfirmEmail, r.controllers.AppAccessClaimsMiddleware, r.controllers.ConfirmUser)
	router.Post(paths.AuthLogin, r.controllers.AppAccessClaimsMiddleware, r.controllers.LoginUser)
	router.Post(
		paths.AuthLogin2FA,
		r.controllers.UserClaimsMiddleware(services.AppKeyName2FA),
		r.controllers.TwoFactorLoginUser,
	)
	router.Post(paths.AuthRefresh, r.controllers.AppAccessClaimsMiddleware, r.controllers.RefreshUser)
	router.Post(
		paths.AuthLogout,
		r.controllers.UserClaimsMiddleware(services.AppKeyNameAccess),
		r.controllers.LogoutUser,
	)
}
