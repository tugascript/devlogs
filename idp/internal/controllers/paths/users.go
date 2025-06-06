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

package paths

const (
	UsersBase string = "/users"

	UsersSingle     string = "/:userIDOrUsername"
	UsersIDSingle   string = "/:userID"
	UsersIDPassword string = "/:userID/password"
)
