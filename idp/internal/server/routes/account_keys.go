package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AccountKeysRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountKeysBase)

	router.Post(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.CreateAccountKeys,
	)
	router.Get(
		paths.Base,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ListAccountKeys,
	)
	router.Get(
		paths.AccountKeysSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.GetSingleAccountKeys,
	)
	router.Patch(
		paths.AccountKeysRefreshSecret,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.RefreshAccountKeysSecret,
	)
	router.Patch(
		paths.AccountKeysSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountKeys,
	)
	router.Delete(
		paths.AccountKeysSingle,
		r.controllers.AccountAccessClaimsMiddleware,
		r.controllers.AdminScopeMiddleware,
		r.controllers.DeleteAccountKeys,
	)
}
