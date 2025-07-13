// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package controllers

import (
	"log/slog"

	"github.com/go-playground/validator/v10"

	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
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
		logger:            logger.With(utils.BaseLayer, utils.ControllersLogLayer),
		services:          services,
		validate:          validate,
		frontendDomain:    frontendDomain,
		backendDomain:     backendDomain,
		refreshCookieName: refreshCookieName,
	}
}
