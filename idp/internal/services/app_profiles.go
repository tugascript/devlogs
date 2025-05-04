// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const appProfilesLocation string = "app_profiles"

type GetAppProfileByIDsOptions struct {
	RequestID string
	AppID     int32
	UserID    int32
}

func (s *Services) GetAppProfileByIDs(
	ctx context.Context,
	opts GetAppProfileByIDsOptions,
) (dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appProfilesLocation, "GetAppProfileByIDs").With(
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Getting app profile by IDs...")

	appProfile, err := s.database.FindAppProfileByAppIDAndUserID(ctx, database.FindAppProfileByAppIDAndUserIDParams{
		AppID:  opts.AppID,
		UserID: opts.UserID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App profile not found")
			return dtos.AppProfileDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Error getting app profile", "error", err)
		return dtos.AppProfileDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App profile found")
	return dtos.MapAppProfileToDTO(&appProfile)
}
