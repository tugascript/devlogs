package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type EmailUpdatePrefixType string

const (
	emailUpdatePrefix   string = "email_update"
	emailUpdateLocation string = "email_update"

	EmailUpdateAccountPrefix EmailUpdatePrefixType = "account"
	EmailUpdateUserPrefix    EmailUpdatePrefixType = "user"
)

type SaveUpdateEmailRequestOptions struct {
	RequestID       string
	PrefixType      EmailUpdatePrefixType
	ID              int
	Email           string
	DurationSeconds int64
}

func (c *Cache) SaveUpdateEmailRequest(ctx context.Context, opts SaveUpdateEmailRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  emailUpdateLocation,
		Method:    "SaveUpdateEmailRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"id", opts.ID,
	)
	logger.DebugContext(ctx, "Saving update email request...")

	key := fmt.Sprintf("%s:%s:%d", emailUpdatePrefix, opts.PrefixType, opts.ID)
	val := []byte(opts.Email)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update email request", "error", err)
		return err
	}

	return nil
}

type GetUpdateEmailRequestOptions struct {
	RequestID  string
	PrefixType EmailUpdatePrefixType
	ID         int
}

func (c *Cache) GetUpdateEmailRequest(ctx context.Context, opts GetUpdateEmailRequestOptions) (string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  emailUpdateLocation,
		Method:    "GetUpdateEmailRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"id", opts.ID,
	)
	logger.DebugContext(ctx, "Getting update email request...")

	key := fmt.Sprintf("%s:%s:%d", emailUpdatePrefix, opts.PrefixType, opts.ID)
	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the update email request", "error", err)
		return "", false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "Update email request not found")
		return "", false, nil
	}

	return string(valByte), true, nil
}
