package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) HealthRoutes(app *fiber.App) {
	app.Get(paths.Health, r.controllers.HealthCheck)
}
