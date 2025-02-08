package validations

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

const slugValidatorTag string = "slug"

func slugValidator(fl validator.FieldLevel) bool {
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
