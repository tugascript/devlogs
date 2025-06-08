// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appsLocation string = "apps"

type CreateAppOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Type            string
	Name            string
	UsernameColumn  string
}

func (s *Services) CreateApp(ctx context.Context, opts CreateAppOptions) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateApp").With(
		"accountPublicID", opts.AccountPublicID,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating app...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}

	name := utils.Capitalized(opts.Name)
	count, err := s.database.CountAppsByNameAndAccountID(ctx, database.CountAppsByNameAndAccountIDParams{
		AccountID: accountDTO.ID(),
		Name:      name,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count the apps", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.InfoContext(ctx, "App name already in use for given account")
		return dtos.AppDTO{}, exceptions.NewConflictError("App name already in use")
	}

	clientId, err := utils.Base62UUID()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client ID", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	clientSecret, err := utils.GenerateBase64Secret(32)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt client secret", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	app, err := s.database.CreateApp(ctx, database.CreateAppParams{
		AccountID:      accountDTO.ID(),
		Name:           name,
		Type:           opts.Type,
		UsernameColumn: opts.UsernameColumn,
		ClientID:       clientId,
		ClientSecret:   hashedSecret,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App created successfully")
	return dtos.MapAppToDTOWithSecret(&app, clientSecret)
}

type GetAppByClientIDOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
}

func (s *Services) GetAppByClientID(
	ctx context.Context,
	opts GetAppByClientIDOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppByClientID").With(
		"accountPublicID", opts.AccountPublicID,
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Getting app by client id...")

	app, err := s.database.FindAppByClientID(ctx, opts.ClientID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App not found", "error", err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get app by clientID", "error", err)
		return dtos.AppDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}
	if app.AccountID != accountDTO.ID() {
		logger.WarnContext(ctx, "Current account id is not the app owner", "appAccountId", app.AccountID)
		return dtos.AppDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "App by clientID found successfully")
	return dtos.MapAppToDTO(&app)
}

type GetAppByClientIDVersionAndAccountIDOptions struct {
	RequestID string
	ClientID  string
	Version   int32
	AccountID int32
}

func (s *Services) GetAppByClientIDVersionAndAccountID(
	ctx context.Context,
	opts GetAppByClientIDVersionAndAccountIDOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppByClientIDVersionAndAccountID").With(
		"clientId", opts.ClientID,
		"version", opts.Version,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting app by client id and account id...")

	app, err := s.database.FindAppByClientIDAndVersion(ctx, database.FindAppByClientIDAndVersionParams{
		ClientID: opts.ClientID,
		Version:  opts.Version,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App not found", "error", err)
			return dtos.AppDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by clientID", "error", err)
		return dtos.AppDTO{}, serviceErr
	}
	if app.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "Current account id is not the app owner", "appAccountId", app.AccountID)
		return dtos.AppDTO{}, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "App by clientID found successfully")
	return dtos.MapAppToDTO(&app)
}

type UpdateAppOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
	Name            string
	ConfirmationURI string
	ResetURI        string
	CallbackUris    []string
	LogoutUris      []string
	DefaultScopes   []string
	AuthProviders   []string
	IDTokenTtl      int32
}

func (s *Services) UpdateApp(ctx context.Context, opts UpdateAppOptions) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateApp").With(
		"accountPublicID", opts.AccountPublicID,
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Updating app...")

	app, serviceErr := s.GetAppByClientID(ctx, GetAppByClientIDOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.ClientID,
	})
	if serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}

	name := utils.Capitalized(opts.Name)

	defaultScopesMap, err := mapSliceToJsonMap(opts.DefaultScopes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode user scopes to json map", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	authProvidersMap, err := mapSliceToJsonMap(opts.AuthProviders)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode app providers to json map", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	appModel, err := s.database.UpdateApp(ctx, database.UpdateAppParams{
		ID:              app.ID(),
		Name:            name,
		ConfirmationUri: opts.ConfirmationURI,
		ResetUri:        opts.ResetURI,
		CallbackUris:    opts.CallbackUris,
		LogoutUris:      opts.LogoutUris,
		DefaultScopes:   defaultScopesMap,
		AuthProviders:   authProvidersMap,
		IDTokenTtl:      opts.IDTokenTtl,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App updated successfully")
	return dtos.MapAppToDTO(&appModel)
}

type UpdateAppSecretOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
}

func (s *Services) UpdateAppSecret(
	ctx context.Context,
	opts UpdateAppSecretOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "RefreshAppSecret").With(
		"accountPublicID", opts.AccountPublicID,
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Updating app secret...")

	app, serviceErr := s.GetAppByClientID(ctx, GetAppByClientIDOptions(opts))
	if serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}

	clientSecret, err := utils.GenerateBase64Secret(32)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash client secret", "error", err)
		return dtos.AppDTO{}, exceptions.NewServerError()
	}

	updatedApp, err := s.database.UpdateAppClientSecret(ctx, database.UpdateAppClientSecretParams{
		ID:           int32(app.ID()),
		ClientSecret: hashedSecret,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app secret", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App secret updated successfully")
	return dtos.MapAppToDTOWithSecret(&updatedApp, clientSecret)
}

type DeleteAppOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
}

func (s *Services) DeleteApp(ctx context.Context, opts DeleteAppOptions) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, appsLocation, "DeleteApp").With(
		"accountPublicID", opts.AccountPublicID,
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Deleting app...")

	app, serviceErr := s.GetAppByClientID(ctx, GetAppByClientIDOptions(opts))
	if serviceErr != nil {
		return serviceErr
	}

	if err := s.database.DeleteApp(ctx, int32(app.ID())); err != nil {
		logger.ErrorContext(ctx, "Failed to delete app", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App deleted successfully")
	return nil
}

type ListAccountAppsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int64
	Limit           int64
	Order           string
}

func (s *Services) ListAccountApps(
	ctx context.Context,
	opts ListAccountAppsOptions,
) ([]dtos.AppDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAccountApps").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
	)
	logger.InfoContext(ctx, "Getting account apps...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return nil, 0, serviceErr
	}

	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FindPaginatedAppsByAccountIDOrderedByID(ctx,
			database.FindPaginatedAppsByAccountIDOrderedByIDParams{
				AccountID: accountDTO.ID(),
				Offset:    int32(opts.Offset),
				Limit:     int32(opts.Limit),
			},
		)
	case "name":
		apps, err = s.database.FindPaginatedAppsByAccountIDOrderedByName(ctx,
			database.FindPaginatedAppsByAccountIDOrderedByNameParams{
				AccountID: accountDTO.ID(),
				Offset:    int32(opts.Offset),
				Limit:     int32(opts.Limit),
			},
		)
	default:
		logger.WarnContext(ctx, "Unknown order type, failing", "order", order)
		return nil, 0, exceptions.NewValidationError("Unknown order type")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountAppsByAccountID(ctx, accountDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	appDTOs, serviceErr := utils.MapSliceWithErr(apps, dtos.MapAppToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account keys to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Account apps retrieved successfully")
	return appDTOs, count, nil
}

type FilterAccountAppsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int64
	Limit           int64
	Order           string
	Name            string
}

func (s *Services) FilterAccountApps(
	ctx context.Context,
	opts FilterAccountAppsOptions,
) ([]dtos.AppDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "FilterAccountApps").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"name", opts.Name,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering account apps...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return nil, 0, serviceErr
	}

	name := utils.DbSearch(opts.Name)
	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FilterAppsByNameAndByAccountIDOrderedByID(ctx,
			database.FilterAppsByNameAndByAccountIDOrderedByIDParams{
				AccountID: accountDTO.ID(),
				Name:      name,
				Offset:    int32(opts.Offset),
				Limit:     int32(opts.Limit),
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndByAccountIDOrderedByName(ctx,
			database.FilterAppsByNameAndByAccountIDOrderedByNameParams{
				AccountID: accountDTO.ID(),
				Name:      name,
				Offset:    int32(opts.Offset),
				Limit:     int32(opts.Limit),
			},
		)
	default:
		logger.WarnContext(ctx, "Unknown order type, failing", "order", order)
		return nil, 0, exceptions.NewValidationError("Unknown order type")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to filter account apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountFilteredAppsByNameAndByAccountID(ctx,
		database.CountFilteredAppsByNameAndByAccountIDParams{
			AccountID: accountDTO.ID(),
			Name:      name,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	appDTOs, serviceErr := utils.MapSliceWithErr(apps, dtos.MapAppToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account apps to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Account apps filtered successfully")
	return appDTOs, count, nil
}
