// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validations

import (
	"log/slog"

	"github.com/go-playground/validator/v10"
)

func NewValidator(logger *slog.Logger) *validator.Validate {
	validate := validator.New()
	if err := validate.RegisterValidation(passwordValidatorTag, passwordValidator); err != nil {
		logger.Error("Failed to register password validator", "error", err)
		panic(err)
	}
	if err := validate.RegisterValidation(slugValidatorTag, slugValidator); err != nil {
		logger.Error("Failed to register slug validator", "error", err)
		panic(err)
	}
	if err := validate.RegisterValidation(scopesValidatorTag, scopesValidator); err != nil {
		logger.Error("Failed to register scopes validator", "error", err)
		panic(err)
	}
	return validate
}
