package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AccountsRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AccountsBase)

	router.Get(paths.AccountMe, r.controllers.AccountAccessClaimsMiddleware, r.controllers.GetCurrentAccount)
	router.Patch(paths.AccountPassword, r.controllers.AccountAccessClaimsMiddleware, r.controllers.UpdateAccountPassword)
	router.Patch(paths.AccountPasswordConfirm, r.controllers.AccountAccessClaimsMiddleware, r.controllers.ConfirmUpdateAccountPassword)
	router.Patch(paths.AccountEmail, r.controllers.AccountAccessClaimsMiddleware, r.controllers.UpdateAccountEmail)
	router.Patch(paths.AccountEmailConfirm, r.controllers.AccountAccessClaimsMiddleware, r.controllers.ConfirmUpdateAccountEmail)
}
