package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type DeleteAccountPrefixType string

const (
	deleteAccountPrefix   string = "delete_account"
	deleteAccountLocation string = "email_update"

	DeleteAccountAccountPrefix DeleteAccountPrefixType = "account"
	DeleteAccountUserPrefix    DeleteAccountPrefixType = "user"
)

type SaveDeleteAccountRequestOptions struct {
	RequestID       string
	PrefixType      DeleteAccountPrefixType
	ID              int
	DurationSeconds int64
}

func (c *Cache) SaveDeleteAccountRequest(ctx context.Context, opts SaveDeleteAccountRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  deleteAccountLocation,
		Method:    "SaveDeleteAccountRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"id", opts.ID,
	)
	logger.DebugContext(ctx, "Saving delete account request...")

	key := fmt.Sprintf("%s:%s:%d", deleteAccountPrefix, opts.PrefixType, opts.ID)
	val := []byte("true")
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching delete account request", "error", err)
		return err
	}

	return nil
}

type GetDeleteAccountRequestOptions struct {
	RequestID  string
	PrefixType DeleteAccountPrefixType
	ID         int
}

func (c *Cache) GetDeleteAccountRequest(ctx context.Context, opts GetDeleteAccountRequestOptions) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  deleteAccountLocation,
		Method:    "GetDeleteAccountRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"id", opts.ID,
	)
	logger.DebugContext(ctx, "Getting delete account request...")

	key := fmt.Sprintf("%s:%s:%d", deleteAccountPrefix, opts.PrefixType, opts.ID)
	val, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the delete account request", "error", err)
		return false, err
	}
	if val == nil {
		return false, nil
	}

	return true, nil
}
