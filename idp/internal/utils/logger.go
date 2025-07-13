// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"log/slog"
)

type LogLayer = string

const (
	BaseLayer string = "layer"

	ControllersLogLayer LogLayer = "controllers"
	ServicesLogLayer    LogLayer = "services"
	ProvidersLogLayer   LogLayer = "providers"
)

type LoggerOptions struct {
	Location  string
	Method    string
	RequestID string
}

func BuildLogger(logger *slog.Logger, opts LoggerOptions) *slog.Logger {
	return logger.With(
		"location", opts.Location,
		"method", opts.Method,
		"requestId", opts.RequestID,
	)
}
