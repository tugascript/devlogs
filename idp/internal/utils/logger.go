package utils

import (
	"log/slog"
)

type LogLayer = string

const (
	ControllersLogLayer LogLayer = "controllers"
	ServicesLogLayer    LogLayer = "services"
	ProvidersLogLayer   LogLayer = "providers"
)

type LoggerOptions struct {
	Layer     string
	Location  string
	Method    string
	RequestID string
}

func BuildLogger(logger *slog.Logger, opts LoggerOptions) *slog.Logger {
	return logger.With(
		"layer", opts.Layer,
		"location", opts.Location,
		"method", opts.Method,
		"requestId", opts.RequestID,
	)
}
