package validations

import (
	"github.com/go-playground/validator/v10"
	"regexp"
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
