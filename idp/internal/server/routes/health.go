package routes

import "github.com/gofiber/fiber/v2"

const HealthPath string = "/health"

func (r *Routes) HealthRoutes(app *fiber.App) {
	router := v1PathRouter(app)

	router.Get(HealthPath, r.controllers.HealthCheck)
}
