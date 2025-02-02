package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

const healthLocation string = "health"

func (s *Services) HealthCheck(ctx context.Context, requestID string) *exceptions.ServiceError {
	logger := s.buildLogger(requestID, healthLocation, "HealthCheck")
	logger.InfoContext(ctx, "Performing health check...")

	if err := s.database.Ping(ctx); err != nil {
		logger.ErrorContext(ctx, "Failed to ping database", "error", err)
		return exceptions.NewServerError()
	}
	if err := s.cache.Ping(ctx); err != nil {
		logger.ErrorContext(ctx, "Failed to ping cache", "error", err)
		return exceptions.NewServerError()
	}
	if err := s.vault.Ping(ctx, requestID); err != nil {
		logger.ErrorContext(ctx, "Failed to ping vault", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Service is healthy")
	return nil
}
