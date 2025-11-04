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

func (r *Routes) AuthRoutes(app *fiber.App) {
	router := V1PathRouter(app).Group(paths.AuthBase)
	authProvsReaderMW := r.controllers.ScopeMiddleware(tokens.AccountScopeAuthProvidersRead)

	// Custom auth paths
	router.Post(paths.AuthRegister, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.RegisterAccount},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.RegisterUser},
	))
	router.Post(paths.AuthConfirmEmail, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.ConfirmAccount},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.ConfirmUser},
	))
	router.Post(paths.AuthLogin, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.LoginAccount},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.LoginUser},
	))
	router.Post(
		paths.AuthLogin+paths.Auth2FA,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.TwoFactorLoginAccount,
	)
	router.Post(
		paths.AuthLogin+paths.Auth2FA+paths.Recover,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.RecoverAccount,
	)
	router.Post(paths.AuthRefresh, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.RefreshAccount},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.RefreshUser},
	))
	router.Post(paths.AuthLogout, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.AccountAccessClaimsMiddleware, r.controllers.LogoutAccount},
		[]fiber.Handler{r.controllers.UserAccessClaimsMiddleware, r.controllers.LogoutUser},
	))
	router.Post(paths.AuthForgotPassword, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.ForgotAccountPassword},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.ForgotUserPassword},
	))
	router.Post(paths.AuthResetPassword, r.controllers.HostMiddleware, HostAwareRoute(
		[]fiber.Handler{r.controllers.ResetAccountPassword},
		[]fiber.Handler{r.controllers.AppAccessClaimsMiddleware, r.controllers.ResetUserPassword},
	))
	router.Get(
		paths.AuthProviders,
		r.controllers.AccountAccessClaimsMiddleware,
		authProvsReaderMW,
		r.controllers.ListAccountAuthProviders,
	)
	router.Get(
		paths.AuthSingleProvider,
		r.controllers.AccountAccessClaimsMiddleware,
		authProvsReaderMW,
		r.controllers.GetAccountAuthProvider,
	)

	// 2FA routes
	router.Post(
		paths.Auth2FA,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.CreateAccount2FAConfig,
	)
	router.Get(
		paths.Auth2FA+paths.TwoFADefault,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.GetDefaultAccount2FAConfig,
	)
	router.Get(
		paths.Auth2FA+paths.TwoFASingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.GetAccount2FAConfig,
	)
	router.Patch(
		paths.Auth2FA+paths.TwoFASingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.SetAccount2FAConfigDefault,
	)
	router.Delete(
		paths.Auth2FA+paths.TwoFASingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.DeleteAccount2FAConfig,
	)
	router.Post(
		paths.Auth2FA+paths.TwoFASingle+paths.Confirm,
		r.controllers.TwoFAAccessClaimsMiddleware,
		r.controllers.ConfirmDeleteAccount2FAConfig,
	)
}
