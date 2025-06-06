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

func (r *Routes) OIDCConfigsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.OIDCConfigBase, r.controllers.AccountAccessClaimsMiddleware)

	router.Get(paths.Base, r.controllers.GetOIDCConfig)
	router.Post(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.CreateOIDCConfig)
	router.Put(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.UpdateOIDCConfig)
}
