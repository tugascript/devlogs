package validations

import (
	"time"

	"github.com/go-playground/validator/v10"
)

const timezoneValidatorTag string = "tzdata"

func isValidTimezone(tz string) bool {
	_, err := time.LoadLocation(tz)
	return err == nil
}

func timezoneValidator(fl validator.FieldLevel) bool {
	input, ok := fl.Field().Interface().(string)
	if !ok {
		return false
	}

	return isValidTimezone(input)
}
