// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	appsLocation string = "apps"

	responseTypeCode        string = "code"
	responseTypeCodeIDToken string = "code id_token"

	transportSTDIO          string = "stdio"
	transportStreamableHTTP string = "streamable_http"
	transportHTTP           string = "http"
)

var authCodeAppGrantTypes = []database.GrantType{database.GrantTypeAuthorizationCode, database.GrantTypeRefreshToken}
var deviceGrantTypes = []database.GrantType{
	database.GrantTypeUrnIetfParamsOauthGrantTypeDeviceCode,
	database.GrantTypeRefreshToken,
}

var defaultAllowedScopes = []database.Scopes{database.ScopesOpenid, database.ScopesEmail, database.ScopesProfile}
var defaultDefaultScopes = []database.Scopes{database.ScopesOpenid, database.ScopesEmail}

type GetAppByClientIDAndAccountPublicIDOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
}

func (s *Services) GetAppByClientIDAndAccountPublicID(
	ctx context.Context,
	opts GetAppByClientIDAndAccountPublicIDOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppByClientIDAndAccountPublicID").With(
		"accountPublicID", opts.AccountPublicID,
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Getting app by client id...")

	app, err := s.database.FindAppByClientIDAndAccountPublicID(ctx, database.FindAppByClientIDAndAccountPublicIDParams{
		ClientID:        opts.ClientID,
		AccountPublicID: opts.AccountPublicID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App not found", "error", err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get app by clientID", "error", err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App by clientID found successfully")
	return dtos.MapAppToDTO(&app), nil
}

type GetAppByClientIDAndAccountIDOptions struct {
	RequestID string
	ClientID  string
	AccountID int32
}

func (s *Services) GetAppByClientIDAndAccountID(
	ctx context.Context,
	opts GetAppByClientIDAndAccountIDOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppByClientIDAndAccountID").With(
		"AccountID", opts.AccountID,
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

	if app.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "Current account id is not the app owner", "appAccountId", app.AccountID)
		return dtos.AppDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "App by clientID found successfully")
	return dtos.MapAppToDTO(&app), nil
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
	return dtos.MapAppToDTO(&app), nil
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

	app, serviceErr := s.GetAppByClientIDAndAccountPublicID(ctx, GetAppByClientIDAndAccountPublicIDOptions(opts))
	if serviceErr != nil {
		return serviceErr
	}

	if err := s.database.DeleteApp(ctx, app.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete app", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App deleted successfully")
	return nil
}

type ListAccountAppsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
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

	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FindPaginatedAppsByAccountPublicIDOrderedByID(ctx,
			database.FindPaginatedAppsByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	case "name":
		apps, err = s.database.FindPaginatedAppsByAccountPublicIDOrderedByName(ctx,
			database.FindPaginatedAppsByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
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

	count, err := s.database.CountAppsByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account apps retrieved successfully")
	return utils.MapSlice(apps, dtos.MapAppToDTO), count, nil
}

type FilterAccountAppsByNameOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
	Order           string
	Name            string
}

func (s *Services) FilterAccountAppsByName(
	ctx context.Context,
	opts FilterAccountAppsByNameOptions,
) ([]dtos.AppDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "FilterAccountAppsByName").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"name", opts.Name,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering account apps by name...")

	name := utils.DbSearch(opts.Name)
	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FilterAppsByNameAndByAccountPublicIDOrderedByID(ctx,
			database.FilterAppsByNameAndByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
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

	count, err := s.database.CountFilteredAppsByNameAndByAccountPublicID(ctx,
		database.CountFilteredAppsByNameAndByAccountPublicIDParams{
			AccountPublicID: opts.AccountPublicID,
			Name:            name,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered apps", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account apps filtered successfully")
	return utils.MapSlice(apps, dtos.MapAppToDTO), count, nil
}

func mapAppTypeToDB(appType string) (database.AppType, *exceptions.ServiceError) {
	switch utils.Lowered(appType) {
	case "web":
		return database.AppTypeWeb, nil
	case "spa":
		return database.AppTypeSpa, nil
	case "native":
		return database.AppTypeNative, nil
	case "backend":
		return database.AppTypeBackend, nil
	case "device":
		return database.AppTypeDevice, nil
	case "service":
		return database.AppTypeService, nil
	case "mcp":
		return database.AppTypeMcp, nil
	default:
		return "", exceptions.NewValidationError("Unsupported app type")
	}
}

type FilterAccountAppsByTypeOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
	Order           string
	Type            string
}

func (s *Services) FilterAccountAppsByType(
	ctx context.Context,
	opts FilterAccountAppsByTypeOptions,
) ([]dtos.AppDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "FilterAccountAppsByType").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"type", opts.Type,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering account apps by type...")

	appType, serviceErr := mapAppTypeToDB(opts.Type)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app type", "serviceError", serviceErr)
		return nil, 0, serviceErr
	}

	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FilterAppsByTypeAndByAccountPublicIDOrderedByID(ctx,
			database.FilterAppsByTypeAndByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				AppType:         appType,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByTypeAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByTypeAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				AppType:         appType,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to filter account apps by type", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountFilteredAppsByTypeAndByAccountPublicID(ctx,
		database.CountFilteredAppsByTypeAndByAccountPublicIDParams{
			AccountPublicID: opts.AccountPublicID,
			AppType:         appType,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered apps by type", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account apps filtered by type successfully")
	return utils.MapSlice(apps, dtos.MapAppToDTO), count, nil
}

type FilterAccountAppsByNameAndTypeOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
	Order           string
	Name            string
	Type            string
}

func (s *Services) FilterAccountAppsByNameAndType(
	ctx context.Context,
	opts FilterAccountAppsByNameAndTypeOptions,
) ([]dtos.AppDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "FilterAccountAppsByNameAndType").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"name", opts.Name,
		"type", opts.Type,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering account apps by name and type...")

	appType, serviceErr := mapAppTypeToDB(opts.Type)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app type", "serviceError", serviceErr)
		return nil, 0, serviceErr
	}

	name := utils.DbSearch(opts.Name)
	order := utils.Lowered(opts.Order)

	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByID(ctx,
			database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
				AppType:         appType,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
				AppType:         appType,
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

	count, err := s.database.CountFilteredAppsByNameAndTypeAndByAccountPublicID(ctx,
		database.CountFilteredAppsByNameAndTypeAndByAccountPublicIDParams{
			AccountPublicID: opts.AccountPublicID,
			Name:            name,
			AppType:         appType,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered apps by name and type", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account apps filtered by name and type successfully")
	return utils.MapSlice(apps, dtos.MapAppToDTO), count, nil
}

func mapUsernameColumn(col string) (database.AppUsernameColumn, *exceptions.ServiceError) {
	switch col {
	case "email", "":
		return database.AppUsernameColumnEmail, nil
	case "username":
		return database.AppUsernameColumnUsername, nil
	case "both":
		return database.AppUsernameColumnBoth, nil
	default:
		return "", exceptions.NewValidationError("Unsupported username column")
	}
}

func updateScopeSlices(
	stdScopes *[]database.Scopes,
	customScopes *[]string,
	scopes []string,
) {
	for _, scope := range scopes {
		switch scope {
		case string(database.ScopesOpenid):
			*stdScopes = append(*stdScopes, database.ScopesOpenid)
		case string(database.ScopesProfile):
			*stdScopes = append(*stdScopes, database.ScopesProfile)
		case string(database.ScopesEmail):
			*stdScopes = append(*stdScopes, database.ScopesEmail)
		case string(database.ScopesAddress):
			*stdScopes = append(*stdScopes, database.ScopesAddress)
		case string(database.ScopesPhone):
			*stdScopes = append(*stdScopes, database.ScopesPhone)
		default:
			*customScopes = append(*customScopes, scope)
		}
	}
}

func mapScopesToStandardAndCustomScopes(
	scopes []string,
	defaultScopes []string,
) ([]database.Scopes, []string, []database.Scopes, []string, *exceptions.ServiceError) {
	customScopes := make([]string, 0)
	stdScopes := make([]database.Scopes, 0)
	if len(scopes) == 0 {
		if len(defaultScopes) == 0 {
			return defaultAllowedScopes, customScopes, defaultDefaultScopes, customScopes, nil
		}

		updateScopeSlices(&stdScopes, &customScopes, defaultScopes)
		return stdScopes, customScopes, stdScopes, customScopes, nil
	}

	updateScopeSlices(&stdScopes, &customScopes, scopes)
	defaultStdScopes := make([]database.Scopes, 0)
	defaultCustomScopes := make([]string, 0)
	if len(defaultScopes) == 0 {
		return stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, nil
	}

	scopesSet := utils.SliceToHashSet(scopes)
	for _, s := range defaultScopes {
		if !scopesSet.Contains(s) {
			return nil, nil, nil, nil, exceptions.NewValidationError("Invalid default scope")
		}

		switch s {
		case string(database.ScopesOpenid):
			defaultStdScopes = append(defaultStdScopes, database.ScopesOpenid)
		case string(database.ScopesProfile):
			defaultStdScopes = append(defaultStdScopes, database.ScopesProfile)
		case string(database.ScopesEmail):
			defaultStdScopes = append(defaultStdScopes, database.ScopesEmail)
		case string(database.ScopesAddress):
			defaultStdScopes = append(defaultStdScopes, database.ScopesAddress)
		case string(database.ScopesPhone):
			defaultStdScopes = append(defaultStdScopes, database.ScopesPhone)
		default:
			defaultCustomScopes = append(defaultCustomScopes, s)
		}
	}

	return stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, nil
}

type checkForDuplicateAppsOptions struct {
	requestID string
	accountID int32
	name      string
}

func (s *Services) checkForDuplicateApps(
	ctx context.Context,
	opts checkForDuplicateAppsOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, appsLocation, "checkForDuplicateApps").With(
		"accountID", opts.accountID,
		"name", opts.name,
	)
	logger.InfoContext(ctx, "Checking for duplicate apps...")

	count, err := s.database.CountAppsByAccountIDAndName(ctx, database.CountAppsByAccountIDAndNameParams{
		AccountID: opts.accountID,
		Name:      opts.name,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count apps by name", "error", err)
		return exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "App name already in use")
		return exceptions.NewConflictError("App name already in use")
	}

	logger.InfoContext(ctx, "No duplicate apps found")
	return nil
}

type createAppOptions struct {
	requestID             string
	accountID             int32
	accountPublicID       uuid.UUID
	creationSource        database.CreationSource
	appType               database.AppType
	name                  string
	allowUserRegistration bool
	clientURI             string
	domain                string
	transport             database.Transport
	usernameColumn        database.AppUsernameColumn
	authMethod            database.AuthMethod
	grantTypes            []database.GrantType
	logoURI               string
	tosURI                string
	policyURI             string
	contacts              []string
	softwareID            string
	softwareVersion       string
	scopes                []string
	defaultScopes         []string
	redirectURIs          []string
	responseTypes         []database.ResponseType
}

func (s *Services) createApp(
	ctx context.Context,
	qrs *database.Queries,
	opts createAppOptions,
) (database.App, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "createApp").With(
		"accountPublicId", opts.accountPublicID,
		"name", opts.name,
		"appType", opts.appType,
	)
	logger.InfoContext(ctx, "Creating app...")

	stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, serviceErr := mapScopesToStandardAndCustomScopes(
		opts.scopes,
		opts.defaultScopes,
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map scopes", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:               opts.accountID,
		AccountPublicID:         opts.accountPublicID,
		AppType:                 opts.appType,
		Name:                    opts.name,
		ClientID:                clientID,
		CreationSource:          opts.creationSource,
		ClientUri:               utils.ProcessURL(opts.clientURI),
		AllowUserRegistration:   opts.allowUserRegistration,
		UsernameColumn:          opts.usernameColumn,
		TokenEndpointAuthMethod: opts.authMethod,
		GrantTypes:              opts.grantTypes,
		LogoUri:                 mapEmptyURL(opts.logoURI),
		TosUri:                  mapEmptyURL(opts.tosURI),
		PolicyUri:               mapEmptyURL(opts.policyURI),
		SoftwareID:              opts.softwareID,
		SoftwareVersion:         mapEmptyString(opts.softwareVersion),
		Scopes:                  stdScopes,
		DefaultScopes:           defaultStdScopes,
		CustomScopes:            customScopes,
		DefaultCustomScopes:     defaultCustomScopes,
		Domain:                  opts.domain,
		Transport:               opts.transport,
		ResponseTypes:           opts.responseTypes,
		RedirectUris: utils.MapSlice(opts.redirectURIs, func(t *string) string {
			return utils.ProcessURL(*t)
		}),
		Contacts: utils.MapSlice(opts.contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return database.App{}, err
	}

	logger.InfoContext(ctx, "App created successfully")
	return app, nil
}

func (s *Services) createSingleApp(
	ctx context.Context,
	opts createAppOptions,
) (database.App, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "createApp").With(
		"accountPublicId", opts.accountPublicID,
		"name", opts.name,
		"appType", opts.appType,
	)
	logger.InfoContext(ctx, "Creating app...")

	stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, serviceErr := mapScopesToStandardAndCustomScopes(
		opts.scopes,
		opts.defaultScopes,
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map scopes", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	clientID := utils.Base62UUID()
	app, err := s.database.CreateApp(ctx, database.CreateAppParams{
		AccountID:               opts.accountID,
		AccountPublicID:         opts.accountPublicID,
		CreationSource:          opts.creationSource,
		AppType:                 opts.appType,
		Name:                    opts.name,
		ClientID:                clientID,
		ClientUri:               utils.ProcessURL(opts.clientURI),
		AllowUserRegistration:   opts.allowUserRegistration,
		UsernameColumn:          opts.usernameColumn,
		TokenEndpointAuthMethod: opts.authMethod,
		GrantTypes:              opts.grantTypes,
		LogoUri:                 mapEmptyURL(opts.logoURI),
		TosUri:                  mapEmptyURL(opts.tosURI),
		PolicyUri:               mapEmptyURL(opts.policyURI),
		Contacts: utils.MapSlice(opts.contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		SoftwareID:          opts.softwareID,
		SoftwareVersion:     mapEmptyString(opts.softwareVersion),
		Scopes:              stdScopes,
		DefaultScopes:       defaultStdScopes,
		CustomScopes:        customScopes,
		DefaultCustomScopes: defaultCustomScopes,
		Domain:              opts.domain,
		Transport:           opts.transport,
		RedirectUris: utils.MapSlice(opts.redirectURIs, func(t *string) string {
			return utils.ProcessURL(*t)
		}),
		ResponseTypes: opts.responseTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return database.App{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App created successfully")
	return app, nil
}

func mapStandardTransport(transport string) database.Transport {
	if transport == transportHTTP {
		return database.TransportHttp
	}

	return database.TransportHttps
}

type CreateWebAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	CreationSource        database.CreationSource
	Name                  string
	AllowUserRegistration bool
	UsernameColumn        string
	AuthMethod            string
	Algorithm             string
	ClientURI             string
	Domain                string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	Transport             string
	CallbackURLs          []string
	ResponseTypes         []string
	Scopes                []string
	DefaultScopes         []string
}

func (s *Services) CreateWebApp(
	ctx context.Context,
	opts CreateWebAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateWebApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating web app...")

	authMethod, serviceErr := mapAuthMethod(opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	responseTypes, serviceErr := mapResponseTypes(opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.createApp(ctx, qrs, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		creationSource:        opts.CreationSource,
		appType:               database.AppTypeWeb,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		transport:             mapStandardTransport(opts.Transport),
		usernameColumn:        usernameColumn,
		authMethod:            authMethod,
		grantTypes:            authCodeAppGrantTypes,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		contacts:              opts.Contacts,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		scopes:                opts.Scopes,
		defaultScopes:         opts.DefaultScopes,
		redirectURIs:          opts.CallbackURLs,
		responseTypes:         responseTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethod {
	case AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       accountID,
			accountPublicID: opts.AccountPublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageApp,
			cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AccountID:        accountID,
			AppID:            app.ID,
			CredentialsKeyID: clientKey.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created web app successfully with private key JWT auth method successfully")
		return dtos.MapWebAppWithJWKToDTO(&app, jwk, clientKey.ExpiresAt), nil
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic, AuthMethodClientSecretJWT:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   accountID,
			storageMode: mapCCSecretStorageMode(opts.AuthMethod),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageApp,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: ccID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created web app successfully with client secret auth method successfully")
		return dtos.MapWebAppWithSecretToDTO(&app, secretID, secret, exp), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethod)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

type CreateSPANativeAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	AppType               database.AppType
	CreationSource        database.CreationSource
	Name                  string
	AllowUserRegistration bool
	Domain                string
	Transport             string
	UsernameColumn        string
	ResponseTypes         []string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	CallbackURIs          []string
	Scopes                []string
	DefaultScopes         []string
}

func (s *Services) CreateSPANativeApp(
	ctx context.Context,
	opts CreateSPANativeAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateSPANativeApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating SPA or Native app...")

	responseTypes, serviceErr := mapResponseTypes(opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	app, serviceErr := s.createSingleApp(ctx, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		creationSource:        opts.CreationSource,
		appType:               opts.AppType,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		transport:             mapStandardTransport(opts.Transport),
		usernameColumn:        usernameColumn,
		authMethod:            database.AuthMethodNone,
		grantTypes:            authCodeAppGrantTypes,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		contacts:              opts.Contacts,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		scopes:                opts.Scopes,
		defaultScopes:         opts.DefaultScopes,
		redirectURIs:          opts.CallbackURIs,
		responseTypes:         responseTypes,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created SPA app successfully")
	return dtos.MapWebNativeSPAMCPAppToDTO(&app), nil
}

type CreateBackendAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	CreationSource        database.CreationSource
	Name                  string
	AllowUserRegistration bool
	UsernameColumn        string
	AuthMethod            string
	Algorithm             string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	Domain                string
	Transport             string
	Scopes                []string
	DefaultScopes         []string
}

func (s *Services) CreateBackendApp(
	ctx context.Context,
	opts CreateBackendAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateBackendApp").With(
		"accountPublicId", opts.AccountPublicID.String(),
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating backend app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	authMethod, serviceErr := mapAuthMethod(opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	grantTypes, serviceErr := mapServerGrantTypesFromAuthMethod(opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.createApp(ctx, qrs, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		creationSource:        opts.CreationSource,
		appType:               database.AppTypeBackend,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		transport:             mapStandardTransport(opts.Transport),
		usernameColumn:        usernameColumn,
		authMethod:            authMethod,
		grantTypes:            grantTypes,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		contacts:              opts.Contacts,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		scopes:                opts.Scopes,
		defaultScopes:         opts.DefaultScopes,
		redirectURIs:          make([]string, 0),
		responseTypes:         make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethod {
	case AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       accountID,
			accountPublicID: opts.AccountPublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageApp,
			cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AccountID:        accountID,
			AppID:            app.ID,
			CredentialsKeyID: clientKey.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created backend app successfully with private key JWT auth method successfully")
		return dtos.MapBackendAppWithJWKToDTO(&app, jwk, clientKey.ExpiresAt), nil
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic, AuthMethodClientSecretJWT:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   accountID,
			storageMode: mapCCSecretStorageMode(opts.AuthMethod),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageApp,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: ccID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created backend app successfully with client secret auth method successfully")
		return dtos.MapBackendAppWithSecretToDTO(&app, secretID, secret, exp), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethod)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

type CreateDeviceAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	CreationSource        database.CreationSource
	Name                  string
	AllowUserRegistration bool
	Domain                string
	Transport             string
	UsernameColumn        string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	BackendDomain         string
	AssociatedApps        []string
	Scopes                []string
	DefaultScopes         []string
}

func (s *Services) CreateDeviceApp(
	ctx context.Context,
	opts CreateDeviceAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateDeviceApp").With(
		"accountPublicId", opts.AccountPublicID.String(),
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating device app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, serviceErr := mapScopesToStandardAndCustomScopes(
		opts.Scopes,
		opts.DefaultScopes,
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map scopes", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	clientID := utils.Base62UUID()
	clientURI := utils.ProcessURL(opts.ClientURI)
	if len(opts.AssociatedApps) == 0 {
		app, err := s.database.CreateApp(ctx, database.CreateAppParams{
			AccountID:               accountID,
			AccountPublicID:         opts.AccountPublicID,
			CreationSource:          opts.CreationSource,
			AppType:                 database.AppTypeDevice,
			Name:                    name,
			ClientID:                clientID,
			ClientUri:               clientURI,
			AllowUserRegistration:   opts.AllowUserRegistration,
			UsernameColumn:          usernameColumn,
			TokenEndpointAuthMethod: database.AuthMethodNone,
			GrantTypes:              deviceGrantTypes,
			LogoUri:                 mapEmptyURL(opts.LogoURI),
			TosUri:                  mapEmptyURL(opts.TOSURI),
			PolicyUri:               mapEmptyURL(opts.PolicyURI),
			Contacts: utils.MapSlice(opts.Contacts, func(t *string) string {
				return utils.Lowered(*t)
			}),
			SoftwareID:          opts.SoftwareID,
			SoftwareVersion:     mapEmptyString(opts.SoftwareVersion),
			Scopes:              stdScopes,
			DefaultScopes:       defaultStdScopes,
			CustomScopes:        customScopes,
			DefaultCustomScopes: defaultCustomScopes,
			Domain:              opts.Domain,
			Transport:           mapStandardTransport(opts.Transport),
			RedirectUris:        make([]string, 0),
			ResponseTypes:       make([]database.ResponseType, 0),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created device app successfully")
		return dtos.MapDeviceAppToDTO(&app, make([]database.App, 0), opts.BackendDomain), nil
	}

	expectedCount := len(opts.AssociatedApps)
	relatedApps, err := s.database.FindAppsByClientIDsAndAccountID(ctx, database.FindAppsByClientIDsAndAccountIDParams{
		AccountID: accountID,
		Limit:     int32(expectedCount),
		ClientIds: opts.AssociatedApps,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find related apps", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	foundCount := len(relatedApps)
	if foundCount != expectedCount {
		logger.WarnContext(ctx, "Not all related apps found", "expectedCount", expectedCount, "foundCount", foundCount)
		return dtos.AppDTO{}, exceptions.NewValidationError("Not all related apps found")
	}

	for _, ra := range relatedApps {
		if ra.AppType != database.AppTypeWeb && ra.AppType != database.AppTypeSpa {
			logger.WarnContext(ctx, "Related app is not a web or spa app", "appID", ra.ID)
			return dtos.AppDTO{}, exceptions.NewValidationError("Related app must be a web or SPA app")
		}
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:               accountID,
		AccountPublicID:         opts.AccountPublicID,
		CreationSource:          opts.CreationSource,
		AppType:                 database.AppTypeDevice,
		Name:                    name,
		ClientID:                clientID,
		ClientUri:               clientURI,
		AllowUserRegistration:   opts.AllowUserRegistration,
		UsernameColumn:          usernameColumn,
		TokenEndpointAuthMethod: database.AuthMethodNone,
		GrantTypes:              deviceGrantTypes,
		LogoUri:                 mapEmptyURL(opts.LogoURI),
		TosUri:                  mapEmptyURL(opts.TOSURI),
		PolicyUri:               mapEmptyURL(opts.PolicyURI),
		Contacts: utils.MapSlice(opts.Contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		SoftwareID:          opts.SoftwareID,
		SoftwareVersion:     mapEmptyString(opts.SoftwareVersion),
		Scopes:              stdScopes,
		DefaultScopes:       defaultStdScopes,
		CustomScopes:        customScopes,
		DefaultCustomScopes: defaultCustomScopes,
		Domain:              opts.Domain,
		Transport:           database.TransportHttps,
		RedirectUris:        make([]string, 0),
		ResponseTypes:       make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	for _, ra := range relatedApps {
		if err = qrs.CreateAppRelatedApp(ctx, database.CreateAppRelatedAppParams{
			AccountID:    accountID,
			AppID:        app.ID,
			RelatedAppID: ra.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app device config", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}
	}

	logger.InfoContext(ctx, "Created device app successfully with related app")
	return dtos.MapDeviceAppToDTO(&app, relatedApps, opts.BackendDomain), nil
}

func mapServerGrantTypesFromAuthMethod(authMethod string) ([]database.GrantType, *exceptions.ServiceError) {
	switch authMethod {
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		return []database.GrantType{database.GrantTypeClientCredentials}, nil
	case AuthMethodPrivateKeyJwt, AuthMethodClientSecretJWT:
		return []database.GrantType{
			database.GrantTypeClientCredentials,
			database.GrantTypeUrnIetfParamsOauthGrantTypeJwtBearer,
		}, nil
	default:
		return nil, exceptions.NewValidationError("Unsupported auth method")
	}
}

type CreateServiceAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	CreationSource        database.CreationSource
	Name                  string
	AuthMethod            string
	UsernameColumn        string
	AccountVersion        int32
	AllowUserRegistration bool
	Algorithm             string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	UsersAuthMethod       string
	Domain                string
	Transport             string
	AllowedDomains        []string
	Scopes                []string
	DefaultScopes         []string
}

func (s *Services) CreateServiceApp(
	ctx context.Context,
	opts CreateServiceAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateServiceApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
		"authMethod", opts.AuthMethod,
	)
	logger.InfoContext(ctx, "Creating service app...")

	authMethod, serviceErr := mapAuthMethod(opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	grantTypes, serviceErr := mapServerGrantTypesFromAuthMethod(opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map service grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	userAuthMethod, serviceErr := mapAuthMethod(opts.UsersAuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if userAuthMethod == database.AuthMethodPrivateKeyJwt && len(opts.AllowedDomains) == 0 {
		logger.ErrorContext(ctx, "Allowed domains must be provided for private key JWT auth method")
		return dtos.AppDTO{}, exceptions.NewValidationError("Allowed domains must be provided for private key JWT auth method")
	}

	userGrantTypes, serviceErr := mapServerGrantTypesFromAuthMethod(opts.UsersAuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.createApp(ctx, qrs, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		creationSource:        opts.CreationSource,
		appType:               database.AppTypeService,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		transport:             mapStandardTransport(opts.Transport),
		usernameColumn:        database.AppUsernameColumnEmail,
		authMethod:            authMethod,
		grantTypes:            grantTypes,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		contacts:              opts.Contacts,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		scopes:                opts.Scopes,
		defaultScopes:         opts.DefaultScopes,
		redirectURIs:          make([]string, 0),
		responseTypes:         make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	appService, err := qrs.CreateAppServiceConfig(ctx, database.CreateAppServiceConfigParams{
		AccountID:      accountID,
		AppID:          app.ID,
		UserAuthMethod: userAuthMethod,
		UserGrantTypes: userGrantTypes,
		AllowedDomains: utils.ToEmptySlice(opts.AllowedDomains),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app service config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethod {
	case AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       accountID,
			accountPublicID: opts.AccountPublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageApp,
			cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AccountID:        accountID,
			AppID:            app.ID,
			CredentialsKeyID: clientKey.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created service app successfully with private key JWT auth method successfully")
		return dtos.MapServiceAppWithJWKToDTO(&app, &appService, jwk, clientKey.ExpiresAt), nil
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic, AuthMethodClientSecretJWT:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   accountID,
			storageMode: mapCCSecretStorageMode(opts.AuthMethod),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageApp,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: ccID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created service app successfully with client secret auth method successfully")
		return dtos.MapServiceAppWithSecretToDTO(&app, &appService, secretID, secret, exp), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethod)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

func mapMCPTransport(transport string) (database.Transport, *exceptions.ServiceError) {
	switch transport {
	case transportSTDIO:
		return database.TransportStdio, nil
	case transportStreamableHTTP:
		return database.TransportStreamableHttp, nil
	default:
		return "", exceptions.NewValidationError("Unsupported transport: " + transport)
	}
}

func mapMCPAuthMethod(transport database.Transport, authMethod string) (database.AuthMethod, *exceptions.ServiceError) {
	if transport == database.TransportStdio {
		return database.AuthMethodNone, nil
	}

	switch authMethod {
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		return database.AuthMethodClientSecretPost, nil
	case AuthMethodPrivateKeyJwt:
		return database.AuthMethodPrivateKeyJwt, nil
	default:
		return "", exceptions.NewValidationError("Unsupported auth method: " + authMethod)
	}
}

func mapMCPResponseTypes(
	transport database.Transport,
	responseTypes []string,
) ([]database.ResponseType, *exceptions.ServiceError) {
	if transport == database.TransportStdio {
		return make([]database.ResponseType, 0), nil
	}
	if len(responseTypes) == 0 {
		return []database.ResponseType{database.ResponseTypeCode, database.ResponseTypeCodeidToken}, nil
	}

	rts := make([]database.ResponseType, 0, len(responseTypes))
	for _, rt := range responseTypes {
		switch rt {
		case responseTypeCode:
			rts = append(rts, database.ResponseTypeCode)
		case responseTypeCodeIDToken:
			rts = append(rts, database.ResponseTypeCodeidToken)
		default:
			return nil, exceptions.NewValidationError("Unsupported response type: " + rt)
		}
	}

	return rts, nil
}

type CreateMCPAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	CreationSource        database.CreationSource
	Name                  string
	AllowUserRegistration bool
	UsernameColumn        string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	Scopes                []string
	DefaultScopes         []string
	Transport             string
	AuthMethod            string
	Algorithm             string
	CallbackURIs          []string
	ResponseTypes         []string
	Domain                string
}

func (s *Services) CreateMCPApp(
	ctx context.Context,
	opts CreateMCPAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateMCPApp").With(
		"accountPublicID", opts.AccountPublicID,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating MCP app...")

	transport, serviceErr := mapMCPTransport(opts.Transport)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map MCP transport", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	authMethod, serviceErr := mapMCPAuthMethod(transport, opts.AuthMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map MCP auth method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	responseTypes, serviceErr := mapMCPResponseTypes(transport, opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
		requestID: opts.RequestID,
		accountID: accountID,
		name:      name,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if transport == database.TransportStreamableHttp {
		if len(opts.CallbackURIs) == 0 {
			logger.ErrorContext(ctx, "Callback URIs must be provided for streamable HTTP transport")
			return dtos.AppDTO{}, exceptions.NewValidationError("Callback URIs must be provided for streamable HTTP transport")
		}

		app, serviceErr := s.createSingleApp(ctx, createAppOptions{
			requestID:             opts.RequestID,
			accountID:             accountID,
			accountPublicID:       opts.AccountPublicID,
			creationSource:        opts.CreationSource,
			appType:               database.AppTypeMcp,
			name:                  name,
			allowUserRegistration: opts.AllowUserRegistration,
			clientURI:             opts.ClientURI,
			domain:                opts.Domain,
			transport:             transport,
			usernameColumn:        usernameColumn,
			authMethod:            authMethod,
			grantTypes:            authCodeAppGrantTypes,
			logoURI:               opts.LogoURI,
			tosURI:                opts.TOSURI,
			policyURI:             opts.PolicyURI,
			contacts:              opts.Contacts,
			softwareID:            opts.SoftwareID,
			softwareVersion:       opts.SoftwareVersion,
			scopes:                opts.Scopes,
			defaultScopes:         opts.DefaultScopes,
			redirectURIs:          opts.CallbackURIs,
			responseTypes:         responseTypes,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create MCP app", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created MCP app successfully")
		return dtos.MapWebNativeSPAMCPAppToDTO(&app), nil
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.createApp(ctx, qrs, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		appType:               database.AppTypeMcp,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		transport:             transport,
		usernameColumn:        usernameColumn,
		authMethod:            authMethod,
		grantTypes:            authCodeAppGrantTypes,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		contacts:              opts.Contacts,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		scopes:                opts.Scopes,
		defaultScopes:         opts.DefaultScopes,
		redirectURIs:          make([]string, 0),
		responseTypes:         responseTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app with auth code config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethod {
	case AuthMethodPrivateKeyJwt:
		var dbPrms database.CreateCredentialsKeyParams
		var jwk utils.JWK
		dbPrms, jwk, serviceErr = s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID:       opts.RequestID,
			accountID:       accountID,
			accountPublicID: opts.AccountPublicID,
			expiresIn:       s.accountCCExpDays,
			usage:           database.CredentialsUsageApp,
			cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientKey database.CredentialsKey
		clientKey, err = qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AccountID:        accountID,
			AppID:            app.ID,
			CredentialsKeyID: clientKey.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created service app successfully with private key JWT auth method successfully")
		return dtos.MapMCPAppWithJWKToDTO(&app, jwk, clientKey.ExpiresAt), nil
	case AuthMethodClientSecretPost, AuthMethodClientSecretBasic, AuthMethodClientSecretJWT:
		var ccID int32
		var secretID, secret string
		var exp time.Time
		ccID, secretID, secret, exp, serviceErr = s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
			requestID:   opts.RequestID,
			accountID:   accountID,
			storageMode: mapCCSecretStorageMode(opts.AuthMethod),
			expiresIn:   s.appCCExpDays,
			usage:       database.CredentialsUsageApp,
			dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountID,
			}),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: ccID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created service app successfully with client secret auth method successfully")
		return dtos.MapMCPAppWithSecretToDTO(&app, secretID, secret, exp), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethod)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

type updateAppOptions struct {
	requestID             string
	usernameColumn        database.AppUsernameColumn
	transport             database.Transport
	allowUserRegistration bool
	domain                string
	name                  string
	clientURI             string
	logoURI               string
	tosURI                string
	policyURI             string
	softwareID            string
	softwareVersion       string
	contacts              []string
	redirectURIs          []string
	responseTypes         []database.ResponseType
}

func (s *Services) updateApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	qrs *database.Queries,
	opts updateAppOptions,
) (database.App, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "updateApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating base app...")

	var softwareVersion pgtype.Text
	if opts.softwareVersion != "" {
		if err := softwareVersion.Scan(opts.softwareVersion); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software version", "error", err)
			return database.App{}, err
		}
	}

	app, err := qrs.UpdateApp(ctx, database.UpdateAppParams{
		ID:                    appDTO.ID(),
		Name:                  opts.name,
		UsernameColumn:        opts.usernameColumn,
		ClientUri:             opts.clientURI,
		LogoUri:               mapEmptyURL(opts.logoURI),
		TosUri:                mapEmptyURL(opts.tosURI),
		PolicyUri:             mapEmptyURL(opts.policyURI),
		SoftwareID:            opts.softwareID,
		SoftwareVersion:       softwareVersion,
		Domain:                opts.domain,
		Transport:             opts.transport,
		AllowUserRegistration: opts.allowUserRegistration,
		ResponseTypes:         opts.responseTypes,
		Contacts: utils.MapSlice(opts.contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		RedirectUris: utils.MapSlice(opts.redirectURIs, func(t *string) string {
			return utils.ProcessURL(*t)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app", "error", err)
		return database.App{}, err
	}

	logger.InfoContext(ctx, "Updated base app successfully")
	return app, nil
}

func (s *Services) updateSingleApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts updateAppOptions,
) (database.App, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "updateApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating base app...")

	var softwareVersion pgtype.Text
	if opts.softwareVersion != "" {
		if err := softwareVersion.Scan(opts.softwareVersion); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software version", "error", err)
			return database.App{}, exceptions.NewInternalServerError()
		}
	}

	app, err := s.database.UpdateApp(ctx, database.UpdateAppParams{
		ID:                    appDTO.ID(),
		Name:                  opts.name,
		UsernameColumn:        opts.usernameColumn,
		ClientUri:             opts.clientURI,
		LogoUri:               mapEmptyURL(opts.logoURI),
		TosUri:                mapEmptyURL(opts.tosURI),
		PolicyUri:             mapEmptyURL(opts.policyURI),
		SoftwareID:            opts.softwareID,
		SoftwareVersion:       softwareVersion,
		Domain:                opts.domain,
		Transport:             opts.transport,
		AllowUserRegistration: opts.allowUserRegistration,
		ResponseTypes:         opts.responseTypes,
		Contacts: utils.MapSlice(opts.contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		RedirectUris: utils.MapSlice(opts.redirectURIs, func(t *string) string {
			return utils.ProcessURL(*t)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app", "error", err)
		return database.App{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated base app successfully")
	return app, nil
}

func mapStandardTransportUpdate(
	currentTransport database.Transport,
	transport string,
) database.Transport {
	if transport == transportHTTP {
		return database.TransportHttp
	}

	return currentTransport
}

type UpdateWebSPANativeAppOptions struct {
	RequestID             string
	AccountID             int32
	UsernameColumn        string
	Name                  string
	Domain                string
	Transport             string
	AllowUserRegistration bool
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	SoftwareID            string
	SoftwareVersion       string
	Contacts              []string
	CallbackURIs          []string
	ResponseTypes         []string
}

func (s *Services) UpdateWebSPANativeApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateWebSPANativeAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateWebSPANativeApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
		"appType", appDTO.AppType,
	)
	logger.InfoContext(ctx, "Updating web or SPA or native app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	responseTypes, serviceErr := mapResponseTypes(opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	name := strings.TrimSpace(opts.Name)
	if appDTO.Name != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      name,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	// Default domain/transport to current values when not provided
	domain := opts.Domain
	if strings.TrimSpace(domain) == "" {
		domain = appDTO.Domain
	}

	app, serviceErr := s.updateSingleApp(ctx, appDTO, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        usernameColumn,
		transport:             mapStandardTransportUpdate(appDTO.Transport, opts.Transport),
		domain:                domain,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          opts.CallbackURIs,
		responseTypes:         responseTypes,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to update app", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated web or SPA or native app successfully")
	return dtos.MapWebNativeSPAMCPAppToDTO(&app), nil
}

type UpdateBackendAppOptions struct {
	RequestID             string
	AccountID             int32
	UsernameColumn        string
	Name                  string
	Domain                string
	Transport             string
	AllowUserRegistration bool
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	SoftwareID            string
	SoftwareVersion       string
	Contacts              []string
}

func (s *Services) UpdateBackendApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateBackendAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateBackendApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating backend app...")

	name := strings.TrimSpace(opts.Name)
	if appDTO.Name != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      name,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	// Ensure we always persist a valid domain and transport
	app, err := s.updateApp(ctx, appDTO, qrs, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        usernameColumn,
		domain:                opts.Domain,
		transport:             mapStandardTransportUpdate(appDTO.Transport, opts.Transport),
		allowUserRegistration: opts.AllowUserRegistration,
		name:                  name,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          make([]string, 0),
		responseTypes:         make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update base app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	// Domain is already included in UpdateApp above; nothing else to update for backend
	logger.InfoContext(ctx, "Updated backend app successfully")
	return dtos.MapBackendAppToDTO(&app), nil
}

type UpdateDeviceAppOptions struct {
	RequestID             string
	AccountID             int32
	UsernameColumn        string
	Name                  string
	Domain                string
	Transport             string
	AllowUserRegistration bool
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	SoftwareID            string
	SoftwareVersion       string
	Contacts              []string
	BackendDomain         string
	AssociatedApps        []string
}

func (s *Services) UpdateDeviceApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateDeviceAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateDeviceApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating device app...")

	name := strings.TrimSpace(opts.Name)
	if appDTO.Name != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      name,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	relatedApps, err := s.database.FindRelatedAppsByAppID(ctx, appDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find related apps", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	toDeleteIDs := make([]int32, 0)
	associatedAppSet := utils.SliceToHashSet(opts.AssociatedApps)
	for _, ra := range relatedApps {
		if !associatedAppSet.Contains(ra.ClientID) {
			toDeleteIDs = append(toDeleteIDs, ra.ID)
		}
	}

	toAddClientIDs := make([]string, 0)
	relatedAppsSet := utils.MapSliceToHashSet(relatedApps, func(ra *database.App) string {
		return ra.ClientID
	})
	for _, clientID := range opts.AssociatedApps {
		if !relatedAppsSet.Contains(clientID) {
			toAddClientIDs = append(toAddClientIDs, clientID)
		}
	}

	toAddApps := make([]database.App, 0)
	if len(toAddClientIDs) > 0 {
		toAddApps, err = s.database.FindAppsByClientIDsAndAccountID(ctx, database.FindAppsByClientIDsAndAccountIDParams{
			AccountID: opts.AccountID,
			Limit:     int32(len(toAddClientIDs)),
			ClientIds: toAddClientIDs,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find related apps to add", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if len(toAddApps) != len(toAddClientIDs) {
			logger.WarnContext(ctx, "Not all related apps found for adding", "expectedCount", len(toAddClientIDs), "foundCount", len(toAddApps))
			return dtos.AppDTO{}, exceptions.NewValidationError("Not all related apps found for adding")
		}

		for _, ra := range toAddApps {
			if ra.AppType != database.AppTypeWeb && ra.AppType != database.AppTypeSpa {
				logger.WarnContext(ctx, "Related app is not a web or spa app", "appID", ra.ID)
				return dtos.AppDTO{}, exceptions.NewValidationError("Related app must be a web or SPA app")
			}
		}
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.updateApp(ctx, appDTO, qrs, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        usernameColumn,
		domain:                opts.Domain,
		transport:             mapStandardTransportUpdate(appDTO.Transport, opts.Transport),
		allowUserRegistration: opts.AllowUserRegistration,
		name:                  name,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          make([]string, 0),
		responseTypes:         make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update base app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	if len(toDeleteIDs) > 0 {
		if err = qrs.DeleteAppRelatedAppsByAppIDAndRelatedAppIDs(
			ctx,
			database.DeleteAppRelatedAppsByAppIDAndRelatedAppIDsParams{
				AppID:         app.ID,
				RelatedAppIds: toDeleteIDs,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to delete related apps", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}
	}
	if len(toAddApps) > 0 {
		for _, ra := range toAddApps {
			if err = qrs.CreateAppRelatedApp(ctx, database.CreateAppRelatedAppParams{
				AccountID:    opts.AccountID,
				AppID:        app.ID,
				RelatedAppID: ra.ID,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to create app device config", "error", err)
				serviceErr = exceptions.FromDBError(err)
				return dtos.AppDTO{}, serviceErr
			}
		}
	}
	if len(toDeleteIDs) == 0 && len(toAddClientIDs) == 0 {
		logger.InfoContext(ctx, "Updated device app successfully")
		return dtos.MapDeviceAppToDTO(&app, relatedApps, opts.BackendDomain), nil
	}

	relatedApps, err = qrs.FindRelatedAppsByAppID(ctx, app.ID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find related apps after update", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated device app successfully")
	return dtos.MapDeviceAppToDTO(&app, relatedApps, opts.BackendDomain), nil
}

type UpdateServiceAppOptions struct {
	RequestID             string
	AccountID             int32
	Name                  string
	Domain                string
	Transport             string
	AllowUserRegistration bool
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	SoftwareID            string
	SoftwareVersion       string
	Contacts              []string
	AllowedDomains        []string
}

func (s *Services) UpdateServiceApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateServiceAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateServiceApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating service app...")

	name := strings.TrimSpace(opts.Name)
	if appDTO.Name != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      name,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	app, err := s.updateApp(ctx, appDTO, qrs, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        database.AppUsernameColumnEmail, // Service apps always use email
		transport:             mapStandardTransportUpdate(appDTO.Transport, opts.Transport),
		allowUserRegistration: opts.AllowUserRegistration,
		domain:                opts.Domain,
		name:                  name,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          make([]string, 0),
		responseTypes:         make([]database.ResponseType, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update base app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	serviceConfig, err := qrs.UpdateAppServiceConfig(ctx, database.UpdateAppServiceConfigParams{
		AccountID:      app.AccountID,
		AppID:          app.ID,
		AllowedDomains: utils.ToEmptySlice(opts.AllowedDomains),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app service config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated service app successfully")
	return dtos.MapServiceAppToDTO(&app, &serviceConfig), nil
}

type UpdateMCPAppOptions struct {
	RequestID             string
	AccountID             int32
	UsernameColumn        string
	Name                  string
	Domain                string
	AllowUserRegistration bool
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	SoftwareID            string
	SoftwareVersion       string
	Contacts              []string
	CallbackURIs          []string
	ResponseTypes         []string
}

func (s *Services) UpdateMCPApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateMCPAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateMCPApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating MCP app...")

	name := strings.TrimSpace(opts.Name)
	if appDTO.Name != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      name,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.UsernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	responseTypes, serviceErr := mapMCPResponseTypes(appDTO.Transport, opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	if appDTO.Transport == database.TransportStreamableHttp {
		if len(opts.CallbackURIs) == 0 {
			logger.ErrorContext(ctx, "Callback URIs must be provided for streamable HTTP transport")
			return dtos.AppDTO{}, exceptions.NewValidationError("Callback URIs must be provided for streamable HTTP transport")
		}
	}

	app, err := s.updateSingleApp(ctx, appDTO, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        usernameColumn,
		transport:             appDTO.Transport,
		domain:                opts.Domain,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareID:            opts.SoftwareID,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          utils.ToEmptySlice(opts.CallbackURIs),
		responseTypes:         responseTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update MCP app", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated MCP app successfully")
	return dtos.MapWebNativeSPAMCPAppToDTO(&app), nil
}

type GetAppWithRelatedConfigsOptions struct {
	RequestID       string
	AppClientID     string
	AccountPublicID uuid.UUID
	BackendDomain   string
}

func (s *Services) GetAppWithRelatedConfigs(
	ctx context.Context,
	opts GetAppWithRelatedConfigsOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppWithRelatedConfigs").With(
		"appClientID", opts.AppClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Getting app with related configs...")

	app, err := s.database.FindAppByClientIDAndAccountPublicID(ctx, database.FindAppByClientIDAndAccountPublicIDParams{
		ClientID:        opts.AppClientID,
		AccountPublicID: opts.AccountPublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find app", "error", err)
		return dtos.AppDTO{}, exceptions.FromDBError(err)
	}

	switch app.AppType {
	case database.AppTypeWeb, database.AppTypeSpa, database.AppTypeNative:
		logger.InfoContext(ctx, "Returning app DTO", "appType", app.AppType)
		return dtos.MapWebNativeSPAMCPAppToDTO(&app), nil
	case database.AppTypeBackend:
		return dtos.MapBackendAppToDTO(&app), nil
	case database.AppTypeDevice:
		relatedApps, err := s.database.FindRelatedAppsByAppID(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find related apps", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}
		logger.InfoContext(ctx, "Returning app DTO", "appType", app.AppType)
		return dtos.MapDeviceAppToDTO(&app, relatedApps, opts.BackendDomain), nil
	case database.AppTypeService:
		serviceConfig, err := s.database.FindAppServiceConfig(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find app service config", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}
		logger.InfoContext(ctx, "Returning app DTO", "appType", app.AppType)
		return dtos.MapServiceAppToDTO(&app, &serviceConfig), nil
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", app.AppType)
		return dtos.AppDTO{}, exceptions.NewInternalServerError()
	}
}

type listAppKeysOptions struct {
	requestID string
	appID     int32
	offset    int32
	limit     int32
}

func (s *Services) listAppKeys(
	ctx context.Context,
	opts listAppKeysOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "listAppKeys").With(
		"appID", opts.appID,
	)
	logger.InfoContext(ctx, "Listing app keys...")

	keys, err := s.database.FindPaginatedAppKeysByAppID(
		ctx,
		database.FindPaginatedAppKeysByAppIDParams{
			AppID:  opts.appID,
			Offset: opts.offset,
			Limit:  opts.limit,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find app keys", "error", err)
		return nil, 0, exceptions.NewInternalServerError()
	}

	count, err := s.database.CountAppKeysByAppID(
		ctx,
		opts.appID,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count app keys", "error", err)
		return nil, 0, exceptions.NewInternalServerError()
	}

	keyDTOs := make([]dtos.ClientCredentialsSecretDTO, len(keys))
	for i, key := range keys {
		keyDTO, serviceErr := dtos.MapCredentialsKeyToDTO(&key)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to map app key to DTO", "serviceError", serviceErr)
			return nil, 0, serviceErr
		}
		keyDTOs[i] = keyDTO
	}

	logger.InfoContext(ctx, "App keys retrieved successfully")
	return keyDTOs, count, nil
}

type listAppSecretsOptions struct {
	requestID string
	appID     int32
	offset    int32
	limit     int32
}

func (s *Services) listAppSecrets(
	ctx context.Context,
	opts listAppSecretsOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "listAppSecrets").With(
		"appID", opts.appID,
	)
	logger.InfoContext(ctx, "Listing app secrets...")

	secrets, err := s.database.FindPaginatedAppSecretsByAppID(
		ctx,
		database.FindPaginatedAppSecretsByAppIDParams{
			AppID:  opts.appID,
			Offset: opts.offset,
			Limit:  opts.limit,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find app secrets", "error", err)
		return nil, 0, exceptions.NewInternalServerError()
	}

	count, err := s.database.CountAppSecretsByAppID(
		ctx,
		opts.appID,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count app secrets", "error", err)
		return nil, 0, exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "App secrets retrieved successfully")
	return utils.MapSlice(secrets, dtos.MapCredentialsSecretToDTO), count, nil
}

type ListAppCredentialsSecretsOrKeysOptions struct {
	RequestID       string
	AppClientID     string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
}

func (s *Services) ListAppCredentialsSecretsOrKeys(
	ctx context.Context,
	opts ListAppCredentialsSecretsOrKeysOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "ListAppCredentialsSecretsOrKeys").With(
		"appClientID", opts.AppClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Listing app credentials secrets or keys...")

	appDTO, serviceErr := s.GetAppByClientIDAndAccountPublicID(
		ctx,
		GetAppByClientIDAndAccountPublicIDOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
			ClientID:        opts.AppClientID,
		},
	)
	if serviceErr != nil {
		return nil, 0, serviceErr
	}
	switch appDTO.AppType {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return nil, 0, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService:
		// Backend and Service apps: use keys only when app uses private_key_jwt
		if appDTO.TokenEndpointAuthMethod != database.AuthMethodPrivateKeyJwt {
			return nil, 0, exceptions.NewConflictError("App type does not support secrets or keys")
		}
		return s.listAppKeys(ctx, listAppKeysOptions{
			requestID: opts.RequestID,
			appID:     appDTO.ID(),
			offset:    opts.Offset,
			limit:     opts.Limit,
		})
	case database.AppTypeWeb:
		// Web apps can use client secrets or private key jwt
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt {
			return s.listAppKeys(ctx, listAppKeysOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				offset:    opts.Offset,
				limit:     opts.Limit,
			})
		}
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretBasic ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretPost ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretJwt {
			return s.listAppSecrets(ctx, listAppSecretsOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				offset:    opts.Offset,
				limit:     opts.Limit,
			})
		}

		logger.WarnContext(ctx, "No auth method to list secrets or keys")
		return nil, 0, exceptions.NewConflictError("No auth method to list secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.AppType)
		return nil, 0, exceptions.NewInternalServerError()
	}
}

type getAppKeyByIDOptions struct {
	requestID string
	appID     int32
	publicKID string
}

func (s *Services) getAppKeyByID(
	ctx context.Context,
	opts getAppKeyByIDOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "getAppKeyByID").With(
		"appID", opts.appID,
		"publicKID", opts.publicKID,
	)
	logger.InfoContext(ctx, "Finding app key by ID...")

	key, err := s.database.FindAppKeyByAppIDAndPublicKID(
		ctx,
		database.FindAppKeyByAppIDAndPublicKIDParams{
			AppID:     opts.appID,
			PublicKid: opts.publicKID,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App key not found", "error", err)
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to find app key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewNotFoundError()
	}

	return dtos.MapCredentialsKeyToDTO(&key)
}

type getAppSecretByIDOptions struct {
	requestID string
	appID     int32
	secretID  string
}

func (s *Services) getAppSecretByID(
	ctx context.Context,
	opts getAppSecretByIDOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "getAppSecretByID").With(
		"appID", opts.appID,
		"secretID", opts.secretID,
	)
	logger.InfoContext(ctx, "Finding app secret by ID...")

	secret, err := s.database.FindAppSecretByAppIDAndSecretID(
		ctx,
		database.FindAppSecretByAppIDAndSecretIDParams{
			AppID:    opts.appID,
			SecretID: opts.secretID,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.InfoContext(ctx, "App secret not found", "error", err)
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to find app secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewNotFoundError()
	}

	return dtos.MapCredentialsSecretToDTO(&secret), nil
}

type GetAppCredentialsSecretOrKeyOptions struct {
	RequestID       string
	AppClientID     string
	AccountPublicID uuid.UUID
	SecretID        string
}

func (s *Services) GetAppCredentialsSecretOrKey(
	ctx context.Context,
	opts GetAppCredentialsSecretOrKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "GetAppCredentialsSecretOrKey").With(
		"appClientID", opts.AppClientID,
		"accountPublicID", opts.AccountPublicID,
		"secretID", opts.SecretID,
	)
	logger.InfoContext(ctx, "Getting app credentials secret or key...")

	appDTO, serviceErr := s.GetAppByClientIDAndAccountPublicID(
		ctx,
		GetAppByClientIDAndAccountPublicIDOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
			ClientID:        opts.AppClientID,
		},
	)
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	switch appDTO.AppType {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt {
			return s.getAppKeyByID(ctx, getAppKeyByIDOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				publicKID: opts.SecretID,
			})
		}
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretBasic ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretPost ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretJwt {
			return s.getAppSecretByID(ctx, getAppSecretByIDOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				secretID:  opts.SecretID,
			})
		}

		logger.WarnContext(ctx, "No auth method to get secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to get secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.AppType)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewInternalServerError()
	}
}

type revokeAppSecretOptions struct {
	requestID string
	appID     int32
	secretID  string
}

func (s *Services) revokeAppSecret(
	ctx context.Context,
	opts revokeAppSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "revokeAppSecret").With(
		"appID", opts.appID,
		"secretID", opts.secretID,
	)
	logger.InfoContext(ctx, "Revoking app secret...")

	secretDTO, serviceErr := s.getAppSecretByID(ctx, getAppSecretByIDOptions(opts))
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	secret, err := s.database.RevokeCredentialsSecret(ctx, secretDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to revoke app secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapCredentialsSecretToDTO(&secret), nil
}

type revokeAppKeyOptions struct {
	requestID string
	appID     int32
	publicKID string
}

func (s *Services) revokeAppKey(
	ctx context.Context,
	opts revokeAppKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "revokeAppKey").With(
		"appID", opts.appID,
		"publicKID", opts.publicKID,
	)
	logger.InfoContext(ctx, "Revoking app key...")

	keyDTO, serviceErr := s.getAppKeyByID(ctx, getAppKeyByIDOptions(opts))
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	key, err := s.database.RevokeCredentialsKey(ctx, keyDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to revoke app key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapCredentialsKeyToDTO(&key)
}

type RevokeAppCredentialsSecretOrKeyOptions struct {
	RequestID       string
	AppClientID     string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	SecretID        string
}

func (s *Services) RevokeAppCredentialsSecretOrKey(
	ctx context.Context,
	opts RevokeAppCredentialsSecretOrKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "RevokeAppCredentialsSecretOrKey").With(
		"appClientID", opts.AppClientID,
		"accountPublicID", opts.AccountPublicID,
		"secretID", opts.SecretID,
	)
	logger.InfoContext(ctx, "Revoking app credentials secret or key...")

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	appDTO, serviceErr := s.GetAppByClientIDAndAccountID(
		ctx,
		GetAppByClientIDAndAccountIDOptions{
			RequestID: opts.RequestID,
			AccountID: accountID,
			ClientID:  opts.AppClientID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	switch appDTO.AppType {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt {
			return s.revokeAppKey(ctx, revokeAppKeyOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				publicKID: opts.SecretID,
			})
		}
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretBasic ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretPost ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretJwt {
			return s.revokeAppSecret(ctx, revokeAppSecretOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				secretID:  opts.SecretID,
			})
		}

		logger.WarnContext(ctx, "No auth method to revoke secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to revoke secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.AppType)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewInternalServerError()
	}
}

type rotateAppKeyOptions struct {
	requestID       string
	accountID       int32
	accountPublicID uuid.UUID
	appID           int32
	cryptoSuite     utils.SupportedCryptoSuite
}

func (s *Services) rotateAppKey(
	ctx context.Context,
	opts rotateAppKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "rotateAppKey").With(
		"appID", opts.appID,
	)
	logger.InfoContext(ctx, "Rotating app key...")

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, nil)
	}()

	dbPrms, jwk, serviceErr := s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
		requestID:       opts.requestID,
		accountID:       opts.accountID,
		accountPublicID: opts.accountPublicID,
		expiresIn:       s.accountCCExpDays,
		usage:           database.CredentialsUsageApp,
		cryptoSuite:     opts.cryptoSuite,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	clientKey, err := qrs.CreateCredentialsKey(ctx, dbPrms)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create client key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	if err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
		AccountID:        opts.accountID,
		AppID:            opts.appID,
		CredentialsKeyID: clientKey.ID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App key rotated successfully")
	return dtos.MapCredentialsKeyToDTOWithJWK(&clientKey, jwk), nil
}

type rotateAppSecretOptions struct {
	requestID  string
	accountID  int32
	appID      int32
	authMethod database.AuthMethod
}

func (s *Services) rotateAppSecret(
	ctx context.Context,
	opts rotateAppSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appsLocation, "rotateAppSecret").With(
		"appID", opts.appID,
	)
	logger.InfoContext(ctx, "Rotating app secret...")

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, nil)
	}()

	id, secretID, secret, exp, serviceErr := s.clientCredentialsSecret(ctx, qrs, clientCredentialsSecretOptions{
		requestID:   opts.requestID,
		accountID:   opts.accountID,
		storageMode: mapCCSecretStorageMode(string(opts.authMethod)),
		expiresIn:   s.accountCCExpDays,
		usage:       database.CredentialsUsageApp,
		dekFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.requestID,
			AccountID: opts.accountID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create client credentials secret", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
		AppID:               opts.appID,
		CredentialsSecretID: id,
		AccountID:           opts.accountID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App secret rotated successfully")
	return dtos.CreateCredentialsSecretToDTOWithSecret(id, secretID, secret, exp), nil
}

type RotateAppCredentialsSecretOrKeyOptions struct {
	RequestID       string
	AppClientID     string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Algorithm       string
}

func (s *Services) RotateAppCredentialsSecretOrKey(
	ctx context.Context,
	opts RotateAppCredentialsSecretOrKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "RotateAppCredentialsSecretOrKey").With(
		"appClientID", opts.AppClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Rotating app credentials secret or key...")

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	appDTO, serviceErr := s.GetAppByClientIDAndAccountID(
		ctx,
		GetAppByClientIDAndAccountIDOptions{
			RequestID: opts.RequestID,
			AccountID: accountID,
			ClientID:  opts.AppClientID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	switch appDTO.AppType {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodPrivateKeyJwt {
			return s.rotateAppKey(ctx, rotateAppKeyOptions{
				requestID:       opts.RequestID,
				accountID:       accountID,
				accountPublicID: opts.AccountPublicID,
				appID:           appDTO.ID(),
				cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
			})
		}
		if appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretBasic ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretPost ||
			appDTO.TokenEndpointAuthMethod == database.AuthMethodClientSecretJwt {
			return s.rotateAppSecret(ctx, rotateAppSecretOptions{
				requestID:  opts.RequestID,
				authMethod: appDTO.TokenEndpointAuthMethod,
				accountID:  accountID,
				appID:      appDTO.ID(),
			})
		}

		logger.WarnContext(ctx, "No auth method to rotate secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to rotate secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.AppType)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewInternalServerError()
	}
}
