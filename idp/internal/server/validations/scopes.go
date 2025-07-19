// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validations

import (
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
)

const scopesValidatorTag string = "scopes"

var scopeRegex = regexp.MustCompile(`^[a-zA-Z0-9]+(:[a-zA-Z0-9]+)?`)

func scopesValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	if input == "" {
		return true
	}

	scopes := strings.Split(input, " ")
	for _, scope := range scopes {
		if !scopeRegex.MatchString(scope) {
			return false
		}
	}

	return true
}
