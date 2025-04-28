// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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

	logger.InfoContext(ctx, "Service is healthy")
	return nil
}
