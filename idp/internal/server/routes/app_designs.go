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

func (r *Routes) AppDesignsRoutes(app *fiber.App) {
	appDesigns := v1PathRouter(app).Group(paths.AppsBase + paths.AppsSingle)

	appsWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsWrite)

	appDesigns.Post(
		paths.AppDesignsBase,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.CreateAppDesign,
	)
	appDesigns.Get(
		paths.AppDesignsBase,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.ScopeMiddleware(tokens.AccountScopeAppsWrite),
		r.controllers.GetAppDesign,
	)
	appDesigns.Put(
		paths.AppDesignsBase,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.UpdateAppDesign,
	)
	appDesigns.Delete(
		paths.AppDesignsBase,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.DeleteAppDesign,
	)
}
