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
	router := V1PathRouter(app).Group(paths.AccountsBase+paths.CredentialsBase, r.controllers.NoHostMiddleware)

	credentialsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsWrite)
	credentialsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsRead)

	router.Post(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsWriteScopeMiddleware,
		r.controllers.CreateAccountCredentials,
	)
	router.Get(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsReadScopeMiddleware,
		r.controllers.ListAccountCredentials,
	)
	router.Get(
		paths.CredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsReadScopeMiddleware,
		r.controllers.GetSingleAccountCredentials,
	)
	router.Put(
		paths.CredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsWriteScopeMiddleware,
		r.controllers.UpdateAccountCredentials,
	)
	router.Delete(
		paths.CredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsWriteScopeMiddleware,
		r.controllers.DeleteAccountCredentials,
	)
}

func (r *Routes) AccountCredentialsSecretsRoutes(app *fiber.App) {
	router := V1PathRouter(app).Group(paths.AccountsBase + paths.CredentialsBase)

	credentialsWriteScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsWrite)
	credentialsReadScopeMiddleware := r.controllers.ScopeMiddleware(tokens.AccountScopeCredentialsRead)

	router.Post(
		paths.CredentialsSecrets,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsWriteScopeMiddleware,
		r.controllers.CreateAccountCredentialsSecret,
	)
	router.Get(
		paths.CredentialsSecrets,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsReadScopeMiddleware,
		r.controllers.ListAccountCredentialsSecrets,
	)
	router.Get(
		paths.CredentialsSecretsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsReadScopeMiddleware,
		r.controllers.GetAccountCredentialsSecret,
	)
	router.Delete(
		paths.CredentialsSecretsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		credentialsWriteScopeMiddleware,
		r.controllers.RevokeAccountCredentialsSecret,
	)
}

func (r *Routes) AccountKeysRoutes(app *fiber.App) {
	router := V1PathRouter(app).Group(paths.AccountsBase)

	router.Get(paths.AccountsSingle+paths.Keys, r.controllers.ListAccountCredentialsKeys)
}
