package controllers

import (
	"log/slog"

	"github.com/go-playground/validator/v10"
	"github.com/tugascript/devlogs/idp/internal/services"
)

type Controllers struct {
	logger            *slog.Logger
	services          *services.Services
	validate          *validator.Validate
	frontendDomain    string
	backendDomain     string
	refreshCookieName string
}

func NewControllers(
	logger *slog.Logger,
	services *services.Services,
	validate *validator.Validate,
	frontendDomain,
	backendDomain,
	refreshCookieName string,
) *Controllers {
	return &Controllers{
		logger:            logger,
		services:          services,
		validate:          validate,
		frontendDomain:    frontendDomain,
		backendDomain:     backendDomain,
		refreshCookieName: refreshCookieName,
	}
}
