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

func (r *Routes) AccountCredentialsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase+paths.CredentialsBase, r.controllers.AccountAccessClaimsMiddleware)

	credentialsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsWrite)
	credentialsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsRead)

	router.Post(paths.Base, credentialsWriteScopeMiddleware, r.controllers.CreateAccountCredentials)
	router.Get(paths.Base, credentialsReadScopeMiddleware, r.controllers.ListAccountCredentials)
	router.Get(
		paths.CredentialsSingle,
		credentialsReadScopeMiddleware,
		r.controllers.GetSingleAccountCredentials,
	)
	router.Put(
		paths.CredentialsSingle,
		credentialsWriteScopeMiddleware,
		r.controllers.UpdateAccountCredentials,
	)
	router.Delete(
		paths.CredentialsSingle,
		credentialsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentials,
	)
}

func (r *Routes) AccountCredentialsSecretsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase+paths.CredentialsBase, r.controllers.AccountAccessClaimsMiddleware)

	credentialsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsWrite)
	credentialsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsRead)

	router.Post(
		paths.CredentialsSecrets,
		credentialsWriteScopeMiddleware,
		r.controllers.CreateAccountCredentialsSecret,
	)
	router.Get(
		paths.CredentialsSecrets,
		credentialsReadScopeMiddleware,
		r.controllers.ListAccountCredentialsSecrets,
	)
	router.Get(
		paths.CredentialsSecretsSingle,
		credentialsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsSecret,
	)
	router.Post(
		paths.CredentialsSecretsRevoke,
		credentialsWriteScopeMiddleware,
		r.controllers.RevokeAccountCredentialsSecret,
	)
}

func (r *Routes) AccountKeysRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase)

	router.Get(paths.AccountsSingle+paths.CredentialsKeysBase, r.controllers.ListAccountCredentialsKeys)
}
