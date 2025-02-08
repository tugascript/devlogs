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
	return validate
}
