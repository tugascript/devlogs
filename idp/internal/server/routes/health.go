package routes

import "github.com/gofiber/fiber/v2"

const HealthPath string = "/health"

func (r *Routes) HealthRoutes(app *fiber.App) {
	app.Get(HealthPath, r.controllers.HealthCheck)
}
