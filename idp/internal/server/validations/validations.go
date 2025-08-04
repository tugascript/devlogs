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
	if err := validate.RegisterValidation(timezoneValidatorTag, timezoneValidator); err != nil {
		logger.Error("Failed to register timezone validator", "error", err)
		panic(err)
	}
	if err := validate.RegisterValidation(secretOrKeyValidatorTag, secretOrKeyValidator); err != nil {
		logger.Error("Failed to register secret or key validator", "error", err)
		panic(err)
	}
	if err := validate.RegisterValidation(singleScopeValidatorTag, singleScopeValidator); err != nil {
		logger.Error("Failed to register single scope validator", "error", err)
		panic(err)
	}
	if err := validate.RegisterValidation(multipleScopeValidatorTag, multipleScopeValidator); err != nil {
		logger.Error("Failed to register multiple scope validator", "error", err)
		panic(err)
	}
	return validate
}
