package queue

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/go-playground/validator/v10"
	r "github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/mailer/internal/email"
	"github.com/tugascript/devlogs/mailer/internal/redis"
	"github.com/tugascript/devlogs/mailer/internal/utils"
)

type Queue struct {
	redisClient *redis.RedisClient
	mail        *email.Mail
	logger      *slog.Logger
	validate    *validator.Validate
}

func NewQueue(
	redisClient *redis.RedisClient,
	mail *email.Mail,
	logger *slog.Logger,
	validate *validator.Validate,
) *Queue {
	return &Queue{
		redisClient: redisClient,
		mail:        mail,
		logger:      logger,
		validate:    validate,
	}
}

func (q *Queue) Start(ctx context.Context) {
	logger := utils.BuildLogger(q.logger, utils.LoggerOptions{
		Service:  "mailer",
		Location: "queue",
		Function: "Start",
	})
	logger.InfoContext(ctx, "Starting mailer queue...")

	pubsub := q.redisClient.Subscribe(ctx)
	subChan := pubsub.Channel()
	defer func() {
		if err := pubsub.Close(); err != nil {
			logger.ErrorContext(ctx, "Failed to close redis pubsub", "error", err)
			return
		}

		logger.InfoContext(ctx, "Queue stopped")
	}()

	go func(ch <-chan *r.Message) {
		for {
			select {
			case <-ctx.Done():
				logger.InfoContext(ctx, "Context canceled, stopping queue processing...")
				return
			case msg, ok := <-ch:
				if !ok {
					logger.WarnContext(ctx, "Redis channel closed, stopping queue processing...")
					return
				}

				logger.InfoContext(ctx, "Received message from redis", "message", msg.Payload)

				email := Email{}
				if err := json.Unmarshal([]byte(msg.Payload), &email); err != nil {
					logger.ErrorContext(ctx, "Failed to unmarshal email, skipping message", "error", err)
					continue
				}

				if err := q.validate.StructCtx(ctx, email); err != nil {
					logger.ErrorContext(ctx, "Invalid email, skipping message", "error", err)
					continue
				}

				if err := q.mail.SendMail(email.To, email.Subject, email.Body); err != nil {
					logger.ErrorContext(ctx, "Failed to send email", "error", err)
					logger.InfoContext(ctx, "Publishing email to redis for retry", "email", email.To)

					attempt, ok, err := q.redisClient.Retry(ctx, email.To)
					if err != nil {
						logger.ErrorContext(ctx, "Failed to retry email", "error", err)
						continue
					}

					if !ok {
						logger.InfoContext(ctx, "Max retries reached for email", "email", email.To)
						continue
					}

					if err := q.redisClient.PublishWithTimeout(ctx, msg.Payload, utils.ExponentialTimeout(attempt)); err != nil {
						logger.ErrorContext(ctx, "Failed to publish email to redis", "error", err)
					}
					continue
				} else {
					logger.InfoContext(ctx, "Email sent successfully", "email", email.To)
				}
			}
		}
	}(subChan)
}
