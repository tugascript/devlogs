// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package validations

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

const scopesValidatorTag string = "scopes"

func scopesValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	if input == "" {
		return true
	}

	re, err := regexp.Compile(`^[a-zA-Z0-9]+(:[a-zA-Z0-9]+)?(\s[a-zA-Z0-9]+(:[a-zA-Z0-9]+)?)*$`)
	if err != nil {
		return false
	}

	return re.MatchString(input)
}
