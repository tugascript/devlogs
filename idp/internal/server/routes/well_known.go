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

func (r *Routes) WellKnownRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.WellKnownBase, r.controllers.AccountHostMiddleware)

	router.Get(paths.WellKnownJWKs, r.controllers.WellKnownJWKs)
	router.Get(paths.WellKnownOIDC, r.controllers.WellKnownOIDCConfiguration)
}
