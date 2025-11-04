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
	router := V1PathRouter(app).Group(paths.AppsBase)

	appsWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsWrite)
	appsReadScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsRead)

	router.Post(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.CreateApp,
	)
	router.Get(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		appsReadScope,
		r.controllers.ListApps,
	)
	router.Get(
		paths.AppsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		appsReadScope,
		r.controllers.GetAppWithRelatedConfigs,
	)
	router.Put(
		paths.AppsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.UpdateApp,
	)
	router.Delete(
		paths.AppsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.DeleteApp,
	)
}

func (r *Routes) AppSecretsRoutes(app *fiber.App) {
	router := V1PathRouter(app).Group(paths.AppsBase)

	appsWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsWrite)
	appsReadScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsRead)

	router.Post(
		paths.CredentialsSecrets,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.CreateAppSecret,
	)
	router.Get(
		paths.CredentialsSecrets,
		r.controllers.AccountAccessClaimsMiddleware,
		appsReadScope,
		r.controllers.ListAppSecrets,
	)
	router.Get(
		paths.CredentialsSecretsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		appsReadScope,
		r.controllers.GetAppSecret,
	)
	router.Delete(
		paths.CredentialsSecretsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		appsWriteScope,
		r.controllers.RevokeAppSecret,
	)
}

func (r *Routes) AppDynamicRegistrationConfigRoutes(app *fiber.App) {
	router := V1PathRouter(app).Group(paths.AppsBase + paths.DynamicRegistrationBase + paths.Config)

	appsConfigsWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsConfigsWrite)
	appsConfigsReadScope := r.controllers.ScopeMiddleware(tokens.AccountScopeAppsConfigsRead)

	router.Get(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		appsConfigsReadScope,
		r.controllers.GetAppDynamicRegistrationConfig,
	)
	router.Put(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		appsConfigsWriteScope,
		r.controllers.UpsertAppDynamicRegistrationConfig,
	)
	router.Delete(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		appsConfigsWriteScope,
		r.controllers.DeleteAppDynamicRegistrationConfig,
	)
}
