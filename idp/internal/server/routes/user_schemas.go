package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) UserSchemasRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.UserSchemasBase, r.controllers.AccountAccessClaimsMiddleware)

	router.Post(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.CreateUserSchema)
	router.Put(paths.Base, r.controllers.AdminScopeMiddleware, r.controllers.UpdateUserSchema)
	router.Get(paths.Base, r.controllers.GetUserSchema)
}
