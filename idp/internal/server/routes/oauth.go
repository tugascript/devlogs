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
		r.controllers.GlobalOAuthPublicJWKs,
		r.controllers.AccountDistributedOAuthPublicJWKs,
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
		HostAwareRoute(r.controllers.DynamicRegistrationIATMiddleware, r.controllers.AppDynamicRegistrationIATMiddleware),
		HostAwareRoute(r.controllers.OAuthDynamicRegistration, r.controllers.OAuthAppDynamicRegistration),
	)
	router.Get(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(r.controllers.DynamicRegistrationAccessTokenMiddleware, r.controllers.AppDynamicRegistrationAccessTokenMiddleware),
		HostAwareRoute(r.controllers.OAuthDynamicRegistrationGet, r.controllers.OAuthAppDynamicRegistrationGet),
	)
	router.Put(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(r.controllers.DynamicRegistrationAccessTokenMiddleware, r.controllers.AppDynamicRegistrationAccessTokenMiddleware),
		HostAwareRoute(r.controllers.OAuthDynamicRegistrationUpdate, r.controllers.OAuthAppDynamicRegistrationUpdate),
	)
	router.Delete(
		paths.OAuthRegisterClient,
		r.controllers.HostMiddleware,
		HostAwareRoute(r.controllers.DynamicRegistrationAccessTokenMiddleware, r.controllers.AppDynamicRegistrationAccessTokenMiddleware),
		HostAwareRoute(r.controllers.OAuthDynamicRegistrationDelete, r.controllers.OAuthAppDynamicRegistrationDelete),
	)

	router.All(paths.OAuthRegisterClient, func(ctx fiber.Ctx) error {
		ctx.Set(fiber.HeaderAllow, "GET, PUT, DELETE")
		return ctx.SendStatus(fiber.StatusMethodNotAllowed)
	})

	// Initial Access Token (IAT) routes
	iatRouter := router.Group(paths.InitialAccessToken, r.controllers.HostMiddleware)
	iatRouter.Post(
		paths.InitialAccessTokenSign,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AppDynamicRegistrationIATSign,
	)

	// Dynamic Registration IAT Code Exchange flow
	iatRouter.Get(
		paths.OAuthAuth,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATAuth,
			r.controllers.AppsOAuthDynamicRegistrationIATAuth,
		),
	)
	iatRouter.Post(
		paths.OAuthToken,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATToken,
			r.controllers.AppsOAuthDynamicRegistrationIATToken,
		),
	)

	// Dynamic Registration IAT Login flow
	const loginRoute = paths.InitialAccessTokenSingle + paths.AuthLogin
	iatRouter.Get(
		loginRoute,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATLoginGet,
			r.controllers.AppsOAuthDynamicRegistrationIATLoginGet,
		),
	)
	iatRouter.Post(
		loginRoute,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATLoginPost,
			r.controllers.AppsOAuthDynamicRegistrationIATLoginPost,
		),
	)

	// Dynamic Registration IAT 2FA flow
	const twoFAAuthRoute = loginRoute + paths.Auth2FA
	iatRouter.Get(
		twoFAAuthRoute,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIAT2FAGet,
			r.controllers.AppsOAuthDynamicRegistrationIAT2FAGet,
		),
	)
	iatRouter.Post(
		twoFAAuthRoute,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIAT2FAPost,
			r.controllers.AppsOAuthDynamicRegistrationIAT2FAPost,
		),
	)

	// Dynamic Registration IAT External Auth flow
	const extAuthRoute = paths.InitialAccessTokenSingle + paths.InitialAccessTokenAuthEXT
	iatRouter.Get(
		extAuthRoute+paths.InitialAccessTokenProvider,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATExtAuthGet,
			r.controllers.AppsOAuthDynamicRegistrationIATExtAuthGet,
		),
	)
	iatRouter.Post(
		extAuthRoute+paths.OAuthAppleCallback,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATExtAppleCB,
			r.controllers.AppsOAuthDynamicRegistrationIATExtAppleCB,
		),
	)
	iatRouter.Get(
		extAuthRoute+paths.OAuthCallback,
		r.controllers.HostMiddleware,
		HostAwareRoute(
			r.controllers.OAuthDynamicRegistrationIATExtCB,
			r.controllers.AppsOAuthDynamicRegistrationIATExtCB,
		),
	)
}
