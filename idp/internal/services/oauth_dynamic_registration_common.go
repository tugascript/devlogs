// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

func validateOrigin(ctx context.Context, logger *slog.Logger, origin, domain string) *exceptions.ServiceError {
	if origin == "" {
		logger.WarnContext(ctx, "Origin header is missing")
		return exceptions.NewUnauthorizedError()
	}

	parsedOrigin, err := url.Parse(origin)
	if err != nil {
		logger.WarnContext(ctx, "Invalid origin header", "error", err)
		return exceptions.NewUnauthorizedError()
	}
	if parsedOrigin.Host != domain && strings.Contains(parsedOrigin.Host, fmt.Sprintf(".%s", domain)) {
		logger.WarnContext(ctx, "Origin header does not match domain", "originHost", parsedOrigin.Host)
		return exceptions.NewUnauthorizedError()
	}

	return nil
}
