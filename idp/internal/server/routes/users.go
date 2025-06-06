// Copyright (C) 2025 Afonso Barracha
//
// This file is part of TugaScript.
//
// TugaScript is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// TugaScript is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with TugaScript.  If not, see <https://www.gnu.org/licenses/>.

package routes

import (
	"github.com/gofiber/fiber/v2"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

func (r *Routes) UsersRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.UsersBase, r.controllers.AccountAccessClaimsMiddleware)
	usersReadScope := r.controllers.ScopeMiddleware(tokens.AccountScopeUsersRead)
	usersWriteScope := r.controllers.ScopeMiddleware(tokens.AccountScopeUsersWrite)

	router.Get(paths.Base, usersReadScope, r.controllers.ListUsers)
	router.Post(paths.Base, usersWriteScope, r.controllers.CreateUser)

	router.Get(paths.UsersSingle, usersReadScope, r.controllers.GetUser)
	router.Put(paths.UsersIDSingle, usersWriteScope, r.controllers.UpdateUser)
	router.Delete(paths.UsersIDSingle, usersWriteScope, r.controllers.DeleteUser)

	router.Patch(paths.UsersIDPassword, usersWriteScope, r.controllers.UpdateUserPassword)
}
