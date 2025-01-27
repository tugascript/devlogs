package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
)

const appsLocation string = "apps"

type GetAppIDBySlugOptions struct {
	RequestID string
	Slug      string
}

func (s *Services) GetAppIDBySlug(ctx context.Context, opts GetAppIDBySlugOptions) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppIDBySlug")
	logger.DebugContext(ctx, "Getting app AccountID by slug...")

	appID, err := s.cache.GetAppID(ctx, cache.GetAppIDOptions{
		RequestID: opts.RequestID,
		AppSlug:   opts.Slug,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error getting app AccountID by slug", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	if appID == uuid.Nil {
		appID, err = s.database.FindAppIDBySlug(ctx, opts.Slug)

		if err != nil {
			logger.WarnContext(ctx, "App AccountID not found", "error", err)
			return uuid.Nil, exceptions.FromDBError(err)
		}
		if appID == uuid.Nil {
			logger.WarnContext(ctx, "App AccountID not found")
			return uuid.Nil, exceptions.NewNotFoundError()
		}

		err = s.cache.AddAppID(ctx, cache.AddAppIDOptions{
			RequestID: opts.RequestID,
			AppSlug:   opts.Slug,
			AppID:     appID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Error adding app AccountID to cache", "error", err)
			return uuid.Nil, exceptions.NewServerError()
		}
	}

	return appID, nil
}
