package cache

import (
	"context"
	"fmt"
	"github.com/tugascript/devlogs/idp/internal/utils"
	"strconv"
	"time"
)

const (
	accountUsernameLocation string = "account_username"

	accountUsernamePrefix string = "account_username"
)

type AddAccountUsernameOptions struct {
	RequestID string
	ID        int
	Username  string
}

func (c *Cache) AddAccountUsername(ctx context.Context, opts AddAccountUsernameOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  accountUsernameLocation,
		Method:    "AddAccountUsername",
		RequestID: opts.RequestID,
	}).With("accountID", opts.ID)
	logger.DebugContext(ctx, "Adding account username...")

	return c.storage.Set(
		fmt.Sprintf("%s:%s", accountUsernamePrefix, opts.Username),
		[]byte(strconv.Itoa(opts.ID)),
		time.Duration(c.usernameTTL)*time.Second,
	)
}

type GetAccountIDByUsernameOptions struct {
	RequestID string
	Username  string
}

func (c *Cache) GetAccountIDByUsername(ctx context.Context, opts GetAccountIDByUsernameOptions) (int, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  accountUsernameLocation,
		Method:    "GetAccountIDByUsername",
		RequestID: opts.RequestID,
	}).With("username", opts.Username)
	logger.DebugContext(ctx, "Getting account username...")

	val, err := c.storage.Get(fmt.Sprintf("%s:%s", accountUsernamePrefix, opts.Username))
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 0, nil
	}

	id, err := strconv.Atoi(string(val))
	if err != nil {
		return 0, err
	}

	return id, nil
}
