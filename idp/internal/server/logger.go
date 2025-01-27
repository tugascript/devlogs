package server

import (
	"log/slog"
	"os"

	"github.com/tugascript/devlogs/idp/internal/config"
)

func DefaultLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: slog.LevelInfo,
		},
	))
}

func ConfigLogger(cfg config.LoggerConfig) *slog.Logger {
	logLevel := slog.LevelInfo

	if cfg.IsDebug() {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	if cfg.Env() == "production" {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}))
	}

	return logger.With("service", cfg.ServiceName())
}
