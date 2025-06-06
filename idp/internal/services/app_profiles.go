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

type GetAppProfileOptions struct {
	RequestID string
	AppID     int32
	UserID    int32
}

func (s *Services) GetAppProfile(
	ctx context.Context,
	opts GetAppProfileOptions,
) (dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appProfilesLocation, "GetAppProfile").With(
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Getting app profile...")

	appProfile, err := s.database.FindAppProfileByAppIDAndUserID(ctx, database.FindAppProfileByAppIDAndUserIDParams{
		AppID:  opts.AppID,
		UserID: opts.UserID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App profile not found", "error", err)
			return dtos.AppProfileDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get app profile by IDs", "error", err)
		return dtos.AppProfileDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App profile by IDs found successfully")
	return dtos.MapAppProfileToDTO(&appProfile)
}

type CreateAppProfileOptions struct {
	RequestID string
	AccountID int32
	AppID     int32
	UserID    int32
}

func (s *Services) CreateAppProfile(
	ctx context.Context,
	opts CreateAppProfileOptions,
) (dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appProfilesLocation, "CreateAppProfile").With(
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Creating app profile...")

	appProfile, err := s.database.CreateAppProfile(ctx, database.CreateAppProfileParams{
		AccountID: opts.AccountID,
		UserID:    opts.UserID,
		AppID:     opts.AppID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app profile", "error", err)
		return dtos.AppProfileDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App profile created successfully")
	return dtos.MapAppProfileToDTO(&appProfile)
}

type GetOrCreateAppProfileOptions struct {
	RequestID string
	AccountID int32
	AppID     int32
	UserID    int32
}

func (s *Services) GetOrCreateAppProfile(
	ctx context.Context,
	opts GetOrCreateAppProfileOptions,
) (dtos.AppProfileDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appProfilesLocation, "GetOrCreateAppProfile").With(
		"appId", opts.AppID,
		"userId", opts.UserID,
	)
	logger.InfoContext(ctx, "Getting or creating app profile...")

	appProfileDTO, serviceErr := s.GetAppProfile(ctx, GetAppProfileOptions{
		RequestID: opts.RequestID,
		AppID:     opts.AppID,
		UserID:    opts.UserID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get app profile", "serviceErr", serviceErr)
			return dtos.AppProfileDTO{}, serviceErr
		}

		return s.CreateAppProfile(ctx, CreateAppProfileOptions(opts))
	}

	logger.InfoContext(ctx, "App profile found successfully")
	return appProfileDTO, nil
}
