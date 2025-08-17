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

const singleScopeValidatorTag string = "single_scope"

const multipleScopeValidatorTag string = "multiple_scope"

var singleScopeRegex = regexp.MustCompile(`^[a-z\d]+(?:([-_:\.])[a-z\d]+)*$`)
var spacesRegex = regexp.MustCompile(`\s+`)

func singleScopeValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok || input == "" {
		return false
	}

	return singleScopeRegex.MatchString(input)
}

func multipleScopeValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}
	if input == "" {
		return true
	}

	scopes := spacesRegex.Split(input, -1)
	for _, scope := range scopes {
		if !singleScopeRegex.MatchString(scope) {
			return false
		}
	}

	return true
}
