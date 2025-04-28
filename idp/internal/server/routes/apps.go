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

func (r *Routes) AppsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AppsBase, r.controllers.AccountAccessClaimsMiddleware)
	appsWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsWrite)

	router.Get(paths.Base, r.controllers.ListApps)
	router.Post(paths.Base, appsWriteScope, r.controllers.CreateApp)
	router.Get(paths.AppsSingle, r.controllers.GetApp)
	router.Put(paths.AppsSingle, appsWriteScope, r.controllers.UpdateApp)
	router.Delete(paths.AppsSingle, appsWriteScope, r.controllers.DeleteApp)
	router.Patch(paths.AppsRefreshSecret, appsWriteScope, r.controllers.RefreshAppSecret)
}
