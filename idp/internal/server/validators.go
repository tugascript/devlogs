package server

import (
	"github.com/go-playground/validator/v10"
	"regexp"
	"unicode"
)

const slugValidatorTag string = "slug"

func isValidSlug(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	re, err := regexp.Compile(`^[a-z\d]+(?:(-)[a-z\d]+)*$`)
	if err != nil {
		return false
	}

	return re.MatchString(input)
}

const passwordValidatorTag string = "password"

type passwordValidity struct {
	hasLowercase bool
	hasUppercase bool
	hasNumber    bool
	hasSymbol    bool
}

func passwordValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	if len(input) < 8 {
		return false
	}

	var validity passwordValidity

	for _, char := range input {
		switch {
		case unicode.IsLower(char):
			validity.hasLowercase = true
		case unicode.IsUpper(char):
			validity.hasUppercase = true
		case unicode.IsNumber(char):
			validity.hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			validity.hasSymbol = true
		}
	}

	return validity.hasLowercase && validity.hasUppercase && validity.hasNumber && validity.hasSymbol
}
