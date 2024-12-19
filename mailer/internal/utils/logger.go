package utils

import (
	"log/slog"
	"os"
)

type LoggerOptions struct {
	Service  string
	Location string
	Function string
}

func BuildLogger(log *slog.Logger, opts LoggerOptions) *slog.Logger {
	return log.With(
		"service", opts.Service,
		"location", opts.Location,
		"function", opts.Function,
	)
}

func DefaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
}

func InitialLogger(env string, debug bool) *slog.Logger {
	logLevel := slog.LevelInfo

	if debug {
		logLevel = slog.LevelDebug
	}
	if env == "production" {
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}

	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
}
