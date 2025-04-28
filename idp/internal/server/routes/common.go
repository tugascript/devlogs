// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import "github.com/gofiber/fiber/v2"

const V1Path string = "/v1"

func v1PathRouter(app *fiber.App) fiber.Router {
	return app.Group(V1Path)
}
