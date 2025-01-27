package exceptions

import (
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	CodeValidation           string = "VALIDATION"
	CodeConflict             string = "CONFLICT"
	CodeInvalidEnum          string = "INVALID_ENUM"
	CodeNotFound             string = "NOT_FOUND"
	CodeUnknown              string = "UNKNOWN"
	CodeServerError          string = "SERVER_ERROR"
	CodeUnauthorized         string = "UNAUTHORIZED"
	CodeForbidden            string = "FORBIDDEN"
	CodeUnsupportedMediaType string = "UNSUPPORTED_MEDIA_TYPE"
)

const (
	MessageDuplicateKey string = "Resource already exists"
	MessageNotFound     string = "Resource not found"
	MessageUnknown      string = "Something went wrong"
	MessageUnauthorized string = "Unauthorized"
	MessageForbidden    string = "Forbidden"
)

type ServiceError struct {
	Code    string
	Message string
}

func NewError(code string, message string) *ServiceError {
	return &ServiceError{
		Code:    code,
		Message: message,
	}
}

func NewNotFoundError() *ServiceError {
	return NewError(CodeNotFound, MessageNotFound)
}

func NewValidationError(message string) *ServiceError {
	return NewError(CodeValidation, message)
}

func NewServerError() *ServiceError {
	return NewError(CodeServerError, MessageUnknown)
}

func NewConflictError(message string) *ServiceError {
	return NewError(CodeConflict, message)
}

func NewUnsupportedMediaTypeError(message string) *ServiceError {
	return NewError(CodeUnsupportedMediaType, message)
}

func NewUnauthorizedError() *ServiceError {
	return NewError(CodeUnauthorized, MessageUnauthorized)
}

func NewForbiddenError() *ServiceError {
	return NewError(CodeForbidden, MessageForbidden)
}

func (e *ServiceError) Error() string {
	return e.Message
}

func FromDBError(err error) *ServiceError {
	if errors.Is(err, pgx.ErrNoRows) {
		return NewError(CodeNotFound, MessageNotFound)
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return NewError(CodeConflict, MessageDuplicateKey)
		case "23514":
			return NewError(CodeInvalidEnum, pgErr.Message)
		case "23503":
			return NewError(CodeNotFound, MessageNotFound)
		default:
			return NewError(CodeUnknown, pgErr.Message)
		}
	}

	return NewError(CodeUnknown, MessageUnknown)
}
