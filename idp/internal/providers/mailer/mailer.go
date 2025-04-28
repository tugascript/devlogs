// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package mailer

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/mailer"

type email struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type EmailPublisher struct {
	client         redis.UniversalClient
	pubChannel     string
	frontendDomain string
	logger         *slog.Logger
}

func NewEmailPublisher(
	client redis.UniversalClient,
	pubChannel,
	frontendDomain string,
	logger *slog.Logger,
) *EmailPublisher {
	return &EmailPublisher{
		client:         client,
		pubChannel:     pubChannel,
		frontendDomain: frontendDomain,
		logger:         logger,
	}
}

type PublishEmailOptions struct {
	To        string
	Subject   string
	Body      string
	RequestID string
}

func (e *EmailPublisher) publishEmail(ctx context.Context, opts PublishEmailOptions) error {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  "mailer",
		Method:    "PublishEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Publishing email...")

	message, err := json.Marshal(email{
		To:      opts.To,
		Subject: opts.Subject,
		Body:    opts.Body,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal email", "error", err)
		return err
	}

	return e.client.Publish(ctx, e.pubChannel, string(message)).Err()
}
