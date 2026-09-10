// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/gofiber/fiber/v3"

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
	router.Post(
		paths.OAuthRegister,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			[]fiber.Handler{
				r.controllers.DynamicRegistrationIATMiddleware,
				r.controllers.OAuthDynamicRegistration,
			},
			[]fiber.Handler{
				r.controllers.AppDynamicRegistrationIATMiddleware,
				r.controllers.OAuthAppDynamicRegistration,
			},
		),
	)
	router.Get(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			[]fiber.Handler{
				r.controllers.DynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthDynamicRegistrationGet,
			},
			[]fiber.Handler{
				r.controllers.AppDynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthAppDynamicRegistrationGet,
			},
		),
	)
	router.Put(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			[]fiber.Handler{
				r.controllers.DynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthDynamicRegistrationUpdate,
			},
			[]fiber.Handler{
				r.controllers.AppDynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthAppDynamicRegistrationUpdate,
			},
		),
	)
	router.Delete(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			[]fiber.Handler{
				r.controllers.DynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthDynamicRegistrationDelete,
			},
			[]fiber.Handler{
				r.controllers.AppDynamicRegistrationAccessTokenMiddleware,
				r.controllers.OAuthAppDynamicRegistrationDelete,
			},
		),
	)

	// Initial Access Token (IAT) routes
	iatRouter := router.Group(paths.InitialAccessToken, r.controllers.HostMiddleware)
	iatRouter.Post(
		paths.InitialAccessTokenSign,
		HostAwareRoute(
			[]fiber.Handler{r.controllers.NotFoundHandler},
			[]fiber.Handler{
				r.controllers.AccountAccessClaimsMiddleware,
				r.controllers.AppDynamicRegistrationIATSign,
			},
		),
	)

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
	const extAuthRoute = paths.InitialAccessTokenSingle + paths.InitialAccessTokenAuthEXT
	iatRouter.Get(extAuthRoute+paths.InitialAccessTokenProvider, r.controllers.OAuthDynamicRegistrationIATExtAuthGet)
	iatRouter.Post(extAuthRoute+paths.OAuthAppleCallback, r.controllers.OAuthDynamicRegistrationIATExtAppleCB)
	iatRouter.Get(extAuthRoute+paths.OAuthCallback, r.controllers.OAuthDynamicRegistrationIATExtCB)
}
