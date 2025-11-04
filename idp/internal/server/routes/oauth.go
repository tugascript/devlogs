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
	router := V1PathRouter(app).Group(paths.AuthBase + paths.OAuthBase)

	// Known auth paths (oauth2)
	router.Post(paths.OAuthKeys, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.GlobalOAuthPublicJWKs},
		[]fiber.Handler{r.controllers.AccountDistributedOAuthPublicJWKs},
	))
	router.Post(paths.OAuthToken, r.controllers.AccountOAuthToken)
	router.Get(paths.OAuthAuth, r.controllers.AccountOAuthURL)

	// OAuth2 Callbacks
	router.Post(paths.OAuthAppleCallback, r.controllers.AccountAppleCallback)
	router.Get(paths.OAuthCallback, r.controllers.AccountOAuthCallback)

	// Register
	router.Post(paths.OAuthRegister, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{
			r.controllers.AccountCredentialsDRIATMiddleware,
			r.controllers.OAuthDynamicRegistration,
		},
		[]fiber.Handler{
			// TODO: add app claims for DR
			r.controllers.OAuthDynamicRegistration,
		},
	))

	// Initial Access Token (IAT) routes
	iatRouter := router.Group(paths.InitialAccessToken)

	// Dynamic Registration IAT Code Exchange flow
	iatRouter.Get(paths.OAuthAuth, r.controllers.OAuthDynamicRegistrationIATAuth)
	iatRouter.Post(paths.OAuthToken, r.controllers.OAuthDynamicRegistrationIATToken)

	// Dynamic Registration IAT Login flow
	const loginRoute = paths.InitialAccessTokenSingle + paths.AuthLogin
	iatRouter.Get(loginRoute, r.controllers.OAuthDynamicRegistrationIATLoginGet)
	iatRouter.Post(loginRoute, r.controllers.OAuthDynamicRegistrationIATLoginPost)

	// Dynamic Registration IAT 2FA flow
	const twoFAAuthRoute = loginRoute + paths.Auth2FA
	iatRouter.Get(twoFAAuthRoute, r.controllers.OAuthDynamicRegistrationIAT2FAGet)
	iatRouter.Post(twoFAAuthRoute, r.controllers.OAuthDynamicRegistrationIAT2FAPost)

	// Dynamic Registration IAT External Auth flow
	const extAuthRoute = paths.InitialAccessTokenSingle + paths.OAuthAuth + paths.InitialAccessTokenAuthEXT
	iatRouter.Get(extAuthRoute+paths.InitialAccessTokenProvider, r.controllers.OAuthDynamicRegistrationIATExtAuthGet)
	iatRouter.Post(extAuthRoute+paths.OAuthAppleCallback, r.controllers.OAuthDynamicRegistrationIATExtAppleCB)
	iatRouter.Get(extAuthRoute+paths.OAuthCallback, r.controllers.OAuthDynamicRegistrationIATExtCB)
}
