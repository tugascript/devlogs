package mailer

import (
	"context"
	"encoding/json"
	"idp/internal/utils"
	"log/slog"

	"github.com/redis/go-redis/v9"
)

const logLayer string = "mailer"

type email struct {
	To      string `json:"to"`
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

type EmailPublisher struct {
	client         *redis.Client
	pubChannel     string
	frontendDomain string
	logger         *slog.Logger
}

func NewEmailPublisher(
	client *redis.Client,
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
		Function:  "PublishEmail",
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
