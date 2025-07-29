// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appDesignsLocation string = "app_designs"

type ColorsOptions struct {
	PrimaryColor    string `json:"primary_color"`
	SecondaryColor  string `json:"secondary_color"`
	BackgroundColor string `json:"background_color"`
	TextColor       string `json:"text_color"`
}

func (c *ColorsOptions) ToUppercase() ColorsOptions {
	return ColorsOptions{
		PrimaryColor:    utils.Uppercased(c.PrimaryColor),
		SecondaryColor:  utils.Uppercased(c.SecondaryColor),
		BackgroundColor: utils.Uppercased(c.BackgroundColor),
		TextColor:       utils.Uppercased(c.TextColor),
	}
}

type AppDesignOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccoutVersion   int32
	AppClientID     string
	LightColors     ColorsOptions
	DarkColors      *ColorsOptions
	LogoURL         string
	FaviconURL      string
}

func (s *Services) CreateAppDesign(
	ctx context.Context,
	opts AppDesignOptions,
) (dtos.AppDesignDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDesignsLocation, "CreateAppDesign").With(
		"accountPublicID", opts.AccountPublicID,
		"appClientID", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Creating app design...")

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccoutVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting account ID", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	appDTO, serviceErr := s.GetAppByClientIDAndAccountID(ctx, GetAppByClientIDAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		AccountID: accountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting app", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	count, err := s.database.CountAppDesignsByAppID(ctx, appDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count app designs", "error", err)
		return dtos.AppDesignDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.InfoContext(ctx, "App design already exists", "appID", appDTO.ID())
		return dtos.AppDesignDTO{}, exceptions.NewConflictError("App design already exists for this app")
	}

	lightColors, err := json.Marshal(opts.LightColors.ToUppercase())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal light colors", "error", err)
		return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
	}

	var darkColors []byte
	if opts.DarkColors != nil {
		darkColors, err = json.Marshal(opts.DarkColors.ToUppercase())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal dark colors", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	var logoURL pgtype.Text
	if opts.LogoURL != "" {
		if err := logoURL.Scan(opts.LogoURL); err != nil {
			logger.ErrorContext(ctx, "Failed to scan logo URL", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	var faviconURL pgtype.Text
	if opts.FaviconURL != "" {
		if err := faviconURL.Scan(opts.FaviconURL); err != nil {
			logger.ErrorContext(ctx, "Failed to scan favicon URL", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	appDesign, err := s.database.CreateAppDesign(ctx, database.CreateAppDesignParams{
		AccountID:   accountID,
		AppID:       appDTO.ID(),
		LightColors: lightColors,
		DarkColors:  darkColors,
		LogoUrl:     logoURL,
		FaviconUrl:  faviconURL,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app design", "error", err)
		return dtos.AppDesignDTO{}, exceptions.FromDBError(err)
	}

	appDesignDTO, serviceErr := dtos.MapAppDesignToDTO(&appDesign)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app design to DTO", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App design created", "appDesign", appDesignDTO)
	return appDesignDTO, nil
}

func (s *Services) UpdateAppDesign(
	ctx context.Context,
	opts AppDesignOptions,
) (dtos.AppDesignDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDesignsLocation, "UpdateAppDesign").With(
		"accountPublicID", opts.AccountPublicID,
		"appClientID", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Updating app design...")

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccoutVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting account ID", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	appDTO, serviceErr := s.GetAppByClientIDAndAccountID(ctx, GetAppByClientIDAndAccountIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.AppClientID,
		AccountID: accountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting app", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	appDesign, err := s.database.FindAppDesignByAppID(ctx, appDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App design not found", "error", err)
			return dtos.AppDesignDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Error getting app design", "error", err)
		return dtos.AppDesignDTO{}, serviceErr
	}

	lightColors, err := json.Marshal(opts.LightColors)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal light colors", "error", err)
		return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
	}

	var darkColors []byte
	if opts.DarkColors != nil {
		darkColors, err = json.Marshal(opts.DarkColors)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to marshal dark colors", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	var logoURL pgtype.Text
	if opts.LogoURL != "" {
		if err := logoURL.Scan(opts.LogoURL); err != nil {
			logger.ErrorContext(ctx, "Failed to scan logo URL", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	var faviconURL pgtype.Text
	if opts.FaviconURL != "" {
		if err := faviconURL.Scan(opts.FaviconURL); err != nil {
			logger.ErrorContext(ctx, "Failed to scan favicon URL", "error", err)
			return dtos.AppDesignDTO{}, exceptions.NewInternalServerError()
		}
	}

	appDesign, err = s.database.UpdateAppDesign(ctx, database.UpdateAppDesignParams{
		ID:          appDesign.ID,
		LightColors: lightColors,
		DarkColors:  darkColors,
		LogoUrl:     logoURL,
		FaviconUrl:  faviconURL,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app design", "error", err)
		return dtos.AppDesignDTO{}, exceptions.FromDBError(err)
	}

	appDesignDTO, serviceErr := dtos.MapAppDesignToDTO(&appDesign)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app design to DTO", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App design updated", "appDesign", appDesignDTO)
	return appDesignDTO, nil
}

type GetAppDesignByAppClientIDOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AppClientID     string
}

func (s *Services) GetAppDesign(
	ctx context.Context,
	opts GetAppDesignByAppClientIDOptions,
) (dtos.AppDesignDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDesignsLocation, "GetAppDesign").With(
		"accountPublicID", opts.AccountPublicID,
		"appClientID", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Getting app design...")

	appDTO, serviceErr := s.GetAppByClientIDAndAccountPublicID(ctx, GetAppByClientIDAndAccountPublicIDOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.AppClientID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting app", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	appDesign, err := s.database.FindAppDesignByAppID(ctx, appDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App design not found", "error", err)
			return dtos.AppDesignDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Error getting app design", "error", err)
		return dtos.AppDesignDTO{}, serviceErr
	}

	appDesignDTO, serviceErr := dtos.MapAppDesignToDTO(&appDesign)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app design to DTO", "serviceError", serviceErr)
		return dtos.AppDesignDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App design found", "appDesign", appDesignDTO)
	return appDesignDTO, nil
}

type DeleteAppDesignOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccoutVersion   int32
	AppClientID     string
}

func (s *Services) DeleteAppDesign(
	ctx context.Context,
	opts DeleteAppDesignOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, appDesignsLocation, "DeleteAppDesign").With(
		"accountPublicID", opts.AccountPublicID,
		"appClientID", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Deleting app design...")

	appDTO, serviceErr := s.GetAppByClientIDAndAccountPublicID(ctx, GetAppByClientIDAndAccountPublicIDOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.AppClientID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Error getting app", "serviceError", serviceErr)
		return serviceErr
	}

	appDesign, err := s.database.FindAppDesignByAppID(ctx, appDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App design not found", "error", err)
			return serviceErr
		}
		logger.ErrorContext(ctx, "Error getting app design", "error", err)
		return serviceErr
	}

	if err := s.database.DeleteAppDesign(ctx, appDesign.ID); err != nil {
		logger.ErrorContext(ctx, "Error deleting app design", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App design deleted successfully", "appDesignID", appDesign.ID)
	return nil
}
