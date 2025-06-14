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

func (r *Routes) OAuthRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AuthBase + paths.OAuthBase)

	// Known auth paths (oauth2)
	router.Post(paths.OAuthKeys, r.controllers.AccountOAuthPublicJWKs)
	router.Post(paths.OAuthToken, r.controllers.AccountOAuthToken)

	// OAuth2 log ins
	router.Post(paths.OAuthAppleCallback, r.controllers.AccountAppleCallback)
	router.Get(paths.OAuthURL, r.controllers.AccountOAuthURL)
	router.Get(paths.OAuthCallback, r.controllers.AccountOAuthCallback)
}
