package server

import (
	"github.com/gofiber/fiber/v2"

	"idp/internal/database"
)

type FiberServer struct {
	*fiber.App

	db database.Service
}

func New() *FiberServer {
	server := &FiberServer{
		App: fiber.New(fiber.Config{
			ServerHeader: "idp",
			AppName:      "idp",
		}),

		db: database.New(),
	}

	return server
}
