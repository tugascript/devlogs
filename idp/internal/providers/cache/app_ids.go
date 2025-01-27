package cache

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	appIDPrefix   string = "app_id"
	appIDLocation string = "app_id"
	appIDTTL      int    = 60 * 60 * 24
)

type AddAppIDOptions struct {
	RequestID string
	AppSlug   string
	AppID     uuid.UUID
}

func (c *Cache) AddAppID(ctx context.Context, opts AddAppIDOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  appIDLocation,
		Method:    "AddAppID",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding app AccountID...")
	return c.storage.Set(
		appIDPrefix+":"+opts.AppSlug,
		[]byte(opts.AppID.String()),
		time.Duration(appIDTTL)*time.Second,
	)
}

type GetAppIDOptions struct {
	RequestID string
	AppSlug   string
}

func (c *Cache) GetAppID(ctx context.Context, opts GetAppIDOptions) (uuid.UUID, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  appIDLocation,
		Method:    "GetAppID",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting app AccountID...")
	valByte, err := c.storage.Get(appIDPrefix + ":" + opts.AppSlug)

	if err != nil {
		logger.ErrorContext(ctx, "Error getting app AccountID", "error", err)
		return uuid.Nil, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "App AccountID not found")
		return uuid.Nil, nil
	}

	appID, err := uuid.ParseBytes(valByte)
	if err != nil {
		logger.ErrorContext(ctx, "Error parsing app AccountID", "error", err)
		return uuid.Nil, err
	}
	return appID, nil
}
