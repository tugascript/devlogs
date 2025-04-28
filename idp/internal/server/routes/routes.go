// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package routes

import (
	"github.com/tugascript/devlogs/idp/internal/controllers"
)

type Routes struct {
	controllers *controllers.Controllers
}

func NewRoutes(ctrls *controllers.Controllers) *Routes {
	return &Routes{controllers: ctrls}
}
