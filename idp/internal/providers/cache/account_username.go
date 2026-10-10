package cache

import (
	"context"
	"fmt"
	"strconv"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountUsernameLocation string = "account_username"

	accountUsernamePrefix string = "account_username"
)

type AddAccountUsernameOptions struct {
	RequestID string
	ID        int64
	Username  string
}

func (c *Cache) AddAccountUsername(ctx context.Context, opts AddAccountUsernameOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountUsernameLocation,
		Method:    "AddAccountUsername",
		RequestID: opts.RequestID,
	}).With("accountId", opts.ID)
	logger.DebugContext(ctx, "Adding account username...")

	return c.storage.SetWithContext(
		ctx,
		fmt.Sprintf("%s:%s", accountUsernamePrefix, opts.Username),
		[]byte(strconv.FormatInt(opts.ID, 10)),
		c.accountUsernameTTL,
	)
}

type GetAccountIDByUsernameOptions struct {
	RequestID string
	Username  string
}

func (c *Cache) GetAccountIDByUsername(
	ctx context.Context,
	opts GetAccountIDByUsernameOptions,
) (int64, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountUsernameLocation,
		Method:    "GetAccountIDByUsername",
		RequestID: opts.RequestID,
	}).With("username", opts.Username)
	logger.DebugContext(ctx, "Getting account username...")

	val, err := c.storage.GetWithContext(ctx, fmt.Sprintf("%s:%s", accountUsernamePrefix, opts.Username))
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 0, nil
	}

	id, err := strconv.ParseInt(string(val), 10, 64)
	if err != nil {
		return 0, err
	}

	return id, nil
}
