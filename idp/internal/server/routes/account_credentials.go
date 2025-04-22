package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AccountCredentialsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountCredentialsBase)

	router.Post(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.CreateAccountCredentials,
	)
	router.Get(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ListAccountCredentials,
	)
	router.Get(
		paths.AccountCredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.GetSingleAccountCredentials,
	)
	router.Put(
		paths.AccountCredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountCredentials,
	)
	router.Delete(
		paths.AccountCredentialsSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.DeleteAccountCredentials,
	)
	router.Patch(
		paths.AccountCredentialsRefreshSecret,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.RefreshAccountCredentialsSecret,
	)
}
