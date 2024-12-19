package utils

import "log/slog"

type LoggerOptions struct {
	Layer     string
	Location  string
	Function  string
	RequestID string
}

func BuildLogger(log *slog.Logger, opts LoggerOptions) *slog.Logger {
	return log.With(
		"layer", opts.Layer,
		"location", opts.Location,
		"function", opts.Function,
		"requestId", opts.RequestID,
	)
}
