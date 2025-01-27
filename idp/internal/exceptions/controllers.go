package exceptions

import (
	"strings"
	"unicode"

	"github.com/go-playground/validator/v10"
)

const (
	StatusConflict     string = "Conflict"
	StatusInvalidEnum  string = "BadRequest"
	StatusNotFound     string = "NotFound"
	StatusUnknown      string = "InternalServerError"
	StatusUnauthorized string = "Unauthorized"
	StatusForbidden    string = "Forbidden"
	StatusValidation   string = "Validation"

	OAuthErrorInvalidRequest string = "invalid_request"
	OAuthErrorInvalidGrant   string = "invalid_grant"
	OAuthErrorInvalidScope   string = "invalid_scope"
)

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewErrorResponse(err *ServiceError) ErrorResponse {
	switch err.Code {
	case CodeConflict:
		return ErrorResponse{
			Code:    StatusConflict,
			Message: err.Message,
		}
	case CodeInvalidEnum:
		return ErrorResponse{
			Code:    StatusInvalidEnum,
			Message: err.Message,
		}
	case CodeNotFound:
		return ErrorResponse{
			Code:    StatusNotFound,
			Message: err.Message,
		}
	case CodeValidation:
		return ErrorResponse{
			Code:    StatusValidation,
			Message: err.Message,
		}
	case CodeUnknown:
		return ErrorResponse{
			Code:    StatusUnknown,
			Message: StatusUnknown,
		}
	case CodeUnauthorized:
		return ErrorResponse{
			Code:    StatusUnauthorized,
			Message: StatusUnauthorized,
		}
	case CodeForbidden:
		return ErrorResponse{
			Code:    StatusForbidden,
			Message: StatusForbidden,
		}
	default:
		return ErrorResponse{
			Code:    StatusUnknown,
			Message: err.Message,
		}
	}
}

type FieldError struct {
	Param   string      `json:"param"`
	Message string      `json:"message"`
	Value   interface{} `json:"value"`
}

type ValidationErrorResponse struct {
	Code     string       `json:"code"`
	Message  string       `json:"message"`
	Location string       `json:"location"`
	Fields   []FieldError `json:"fields,omitempty"`
}

const (
	ValidationResponseMessage        string = "Invalid request"
	ValidationResponseLocationBody   string = "body"
	ValidationResponseLocationQuery  string = "query"
	ValidationResponseLocationParams string = "params"
)

func toSnakeCase(camel string) string {
	if camel == strings.ToUpper(camel) {
		return strings.ToLower(camel)
	}

	var result strings.Builder
	for i, char := range camel {
		if unicode.IsUpper(char) {
			lowered := unicode.ToLower(char)
			if i > 0 {
				result.WriteRune('_')
				result.WriteRune(lowered)
				continue
			}

			result.WriteRune(lowered)
		} else {
			result.WriteRune(char)
		}
	}
	return result.String()
}

const (
	fieldErrTagEqField  string = "eqfield"
	fieldErrTagRequired string = "required"
	fieldErrTagEq       string = "eq"

	strFieldErrTagMin   string = "min"
	strFieldErrTagMax   string = "max"
	strFieldErrTagEmail string = "email"
	strFieldErrTagJWT   string = "jwt"
	strFieldErrTagUrl   string = "url"
	strFieldNumber      string = "number"
	strFieldUUID        string = "uuid"

	intFieldErrTagGte string = "gte"
	intFieldErrTagLte string = "lte"

	FieldErrMessageInvalid  string = "must be valid"
	FieldErrMessageRequired string = "must be provided"
	FieldErrMessageEqField  string = "does not match equivalent field"
	FieldErrMessageEq       string = "does not match expected value"

	StrFieldErrMessageEmail  string = "must be a valid email"
	StrFieldErrMessageMin    string = "must be longer"
	StrFieldErrMessageMax    string = "must be shorter"
	StrFieldErrMessageJWT    string = "must be a valid JWT token"
	StrFieldErrMessageUrl    string = "must be a valid URL"
	StrFieldErrMessageNumber string = "must be a number"
	StrFieldErrMessageUUID   string = "must be a valid UUID"

	IntFieldErrMessageLte string = "must be less"
	IntFieldErrMessageGte string = "must be greater"
)

func selectStrErrMessage(tag string) string {
	switch tag {
	case fieldErrTagRequired:
		return FieldErrMessageRequired
	case strFieldErrTagEmail:
		return StrFieldErrMessageEmail
	case strFieldErrTagMin:
		return StrFieldErrMessageMin
	case strFieldErrTagMax:
		return StrFieldErrMessageMax
	case fieldErrTagEqField:
		return FieldErrMessageEqField
	case strFieldErrTagJWT:
		return StrFieldErrMessageJWT
	case strFieldErrTagUrl:
		return StrFieldErrMessageUrl
	case strFieldNumber:
		return StrFieldErrMessageNumber
	case strFieldUUID:
		return StrFieldErrMessageUUID
	case fieldErrTagEq:
		return FieldErrMessageEq
	default:
		return FieldErrMessageInvalid
	}
}

func selectIntErrMessage(tag string) string {
	switch tag {
	case fieldErrTagRequired:
		return FieldErrMessageRequired
	case intFieldErrTagLte:
		return IntFieldErrMessageLte
	case intFieldErrTagGte:
		return IntFieldErrMessageGte
	default:
		return FieldErrMessageInvalid
	}
}

func buildFieldErrorMessage(tag string, val interface{}) string {
	switch val.(type) {
	case string:
		return selectStrErrMessage(tag)
	case int, int16, int32, int64:
		return selectIntErrMessage(tag)
	default:
		return FieldErrMessageInvalid
	}
}

func ValidationErrorResponseFromErr(err *validator.ValidationErrors, location string) ValidationErrorResponse {
	fields := make([]FieldError, len(*err))

	for i, field := range *err {
		value := field.Value()
		fields[i] = FieldError{
			Value:   value,
			Param:   toSnakeCase(field.Field()),
			Message: buildFieldErrorMessage(field.Tag(), value),
		}
	}

	return ValidationErrorResponse{
		Code:     StatusValidation,
		Message:  ValidationResponseMessage,
		Fields:   fields,
		Location: location,
	}
}

func NewValidationErrorResponse(location string, fields []FieldError) ValidationErrorResponse {
	return ValidationErrorResponse{
		Code:     StatusValidation,
		Message:  ValidationResponseMessage,
		Fields:   fields,
		Location: location,
	}
}

func NewEmptyValidationErrorResponse(location string) ValidationErrorResponse {
	return ValidationErrorResponse{
		Code:     StatusValidation,
		Message:  ValidationResponseMessage,
		Location: location,
	}
}

func NewRequestErrorStatus(code string) int {
	switch code {
	case CodeConflict:
		return 409
	case CodeInvalidEnum, CodeValidation:
		return 400
	case CodeNotFound:
		return 404
	case CodeForbidden:
		return 403
	case CodeUnauthorized:
		return 401
	case CodeUnknown:
		return 500
	case CodeUnsupportedMediaType:
		return 415
	default:
		return 500
	}
}

type OAuthErrorResponse struct {
	Error string `json:"error"`
}

func NewOAuthError(message string) OAuthErrorResponse {
	return OAuthErrorResponse{Error: message}
}
