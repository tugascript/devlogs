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

const slugValidatorTag string = "slug"

var slugRegex = regexp.MustCompile(`^[a-z\d]+(?:(-)[a-z\d]+)*$`)

func slugValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	return slugRegex.MatchString(input)
}
