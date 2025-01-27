package routes

import "github.com/gofiber/fiber/v2"

const V1Path string = "/v1"

func v1PathRouter(app *fiber.App) fiber.Router {
	return app.Group(V1Path)
}
