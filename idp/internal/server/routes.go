package server

func (s *FiberServer) RegisterFiberRoutes() {
	s.routes.HealthRoutes(s.App)
	s.routes.AuthRoutes(s.App)
	s.routes.AccountCredentialsRoutes(s.App)
	s.routes.AccountsRoutes(s.App)
}
