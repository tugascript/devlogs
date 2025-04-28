// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package server

func (s *FiberServer) RegisterFiberRoutes() {
	s.routes.HealthRoutes(s.App)
	s.routes.AuthRoutes(s.App)
	s.routes.AccountCredentialsRoutes(s.App)
	s.routes.AccountsRoutes(s.App)
	s.routes.AppsRoutes(s.App)
	s.routes.UserSchemasRoutes(s.App)
}
