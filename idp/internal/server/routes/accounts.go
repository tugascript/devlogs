package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AccountsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase, r.controllers.AccountAccessClaimsMiddleware)

	router.Get(paths.AccountMe, r.controllers.GetCurrentAccount)
	router.Delete(paths.AccountMe, r.controllers.AdminScopeMiddleware, r.controllers.DeleteAccount)
	router.Patch(paths.AccountPassword, r.controllers.AdminScopeMiddleware, r.controllers.UpdateAccountPassword)
	router.Patch(
		paths.AccountPasswordConfirm,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ConfirmUpdateAccountPassword,
	)
	router.Patch(
		paths.AccountEmail,
		r.controllers.AdminScopeMiddleware,
		r.controllers.UpdateAccountEmail,
	)
	router.Patch(
		paths.AccountEmailConfirm,
		r.controllers.AdminScopeMiddleware,
		r.controllers.ConfirmUpdateAccountEmail,
	)
}
