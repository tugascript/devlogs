package cache

import (
	"context"
	"idp/internal/utils"
	"time"
)

const (
	oauthEmailPrefix   string = "oauth_email"
	oauthEmailLocation string = "oauth_email"
)

type AddOAuthEmailOptions struct {
	RequestID       string
	Code            string
	Email           string
	DurationSeconds int64
}

func (c *Cache) AddOAuthEmail(ctx context.Context, opts AddOAuthEmailOptions) error {
	logger := utils.BuildLogger(c.log, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthEmailLocation,
		Function:  "AddOAuthEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding OAuth email...")
	return c.storage.Set(
		oauthEmailPrefix+":"+opts.Code,
		[]byte(opts.Email),
		time.Duration(opts.DurationSeconds)*time.Second,
	)
}

type GetOAuthEmailOptions struct {
	RequestID string
	Code      string
}

func (c *Cache) GetOAuthEmail(ctx context.Context, opts GetOAuthEmailOptions) (string, error) {
	logger := utils.BuildLogger(c.log, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthEmailLocation,
		Function:  "GetOAuthEmail",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting OAuth email...")

	valByte, err := c.storage.Get(oauthEmailPrefix + ":" + opts.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting OAuth email", "error", err)
		return "", err
	}

	if valByte == nil {
		logger.DebugContext(ctx, "OAuth email not found")
		return "", nil
	}

	return string(valByte), nil
}
