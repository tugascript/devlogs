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

const secretOrKeyValidatorTag string = "secret_or_key"

var secretOrKeyRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func secretOrKeyValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	length := len(input)
	if length < 22 || length > 26 {
		return false
	}

	return secretOrKeyRegex.MatchString(input)
}
