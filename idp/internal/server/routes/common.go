// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/gofiber/fiber/v3"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func V1PathRouter(app *fiber.App) fiber.Router {
	return app.Group(paths.V1)
}

func HostAwareRoute(
	normalHandlers []fiber.Handler,
	hostHandlers []fiber.Handler,
) fiber.Handler {
	return func(ctx fiber.Ctx) error {
		hasAccountHost, ok := ctx.Locals("hasAccountHost").(bool)
		ctx.Locals("hostAwareRoute", true)

		if !ok || !hasAccountHost {
			for _, handler := range normalHandlers {
				if err := handler(ctx); err != nil {
					return err
				}
				if ctx.Response().StatusCode() >= fiber.StatusBadRequest {
					return nil
				}
			}

			return nil
		}

		for _, handler := range hostHandlers {
			if err := handler(ctx); err != nil {
				return err
			}
			if ctx.Response().StatusCode() >= fiber.StatusBadRequest {
				return nil
			}
		}

		return nil
	}
}
