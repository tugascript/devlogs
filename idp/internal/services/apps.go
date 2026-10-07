// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"slices"
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
)

var authCodeAppGrantTypes = []database.GrantType{database.GrantTypeAuthorizationCode, database.GrantTypeRefreshToken}
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
				ClientName:      name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				ClientName:      name,
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
			ClientName:      name,
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
	case "native":
		return database.AppTypeNative, nil
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
				ClientName:      name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
				AppType:         appType,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				ClientName:      name,
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
			ClientName:      name,
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

func mapAuthProviders(authProviders []string) ([]database.AuthProvider, *exceptions.ServiceError) {
	if len(authProviders) == 0 {
		return []database.AuthProvider{database.AuthProviderLocal}, nil
	}

	validAuthProviders := make([]database.AuthProvider, 0, len(authProviders))
	for _, provider := range authProviders {
		dbp := database.AuthProvider(provider)
		switch dbp {
		case database.AuthProviderLocal, database.AuthProviderApple, database.AuthProviderFacebook,
			database.AuthProviderGoogle, database.AuthProviderGithub, database.AuthProviderMicrosoft:
			validAuthProviders = append(validAuthProviders, dbp)
		default:
			return nil, exceptions.NewValidationError("Unsupported auth provider: " + provider)
		}
	}

	return validAuthProviders, nil
}

type checkForDuplicateAppsOptions struct {
	requestID  string
	accountID  int32
	name       string
	softwareID string
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

	var count int64
	var err error
	if opts.softwareID != "" {
		count, err = s.database.CountAppsByAccountIDAndCliantNameOrSoftwareID(ctx, database.CountAppsByAccountIDAndCliantNameOrSoftwareIDParams{
			AccountID:  opts.accountID,
			ClientName: opts.name,
			SoftwareID: pgtype.Text{String: opts.softwareID, Valid: true},
		})
	} else {
		count, err = s.database.CountAppsByAccountIDAndName(ctx, database.CountAppsByAccountIDAndNameParams{
			AccountID:  opts.accountID,
			ClientName: opts.name,
		})
	}

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
	creationMethod        database.CreationMethod
	appType               database.AppType
	name                  string
	allowUserRegistration bool
	clientURI             string
	domain                string
	usernameColumn        string
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
	authProviders         []string
}

func (s *Services) createApp(
	ctx context.Context,
	qrs *database.Queries,
	opts createAppOptions,
) (database.App, error) {
	redirectURIs := utils.MapSlice(opts.redirectURIs, func(t *string) string {
		return utils.ProcessURL(*t)
	})
	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	logger := s.buildLogger(opts.requestID, appsLocation, "createApp").With(
		"accountPublicId", opts.accountPublicID,
		"name", opts.name,
		"appType", opts.appType,
	)
	logger.InfoContext(ctx, "Creating app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.usernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	authProviders, serviceErr := mapAuthProviders(opts.authProviders)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth providers", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	derivedDomain, serviceErr := mapDomain(opts.clientURI, opts.domain)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map domain", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

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
		CreationMethod:          opts.creationMethod,
		AppType:                 opts.appType,
		ClientName:              opts.name,
		ClientID:                clientID,
		ClientUri:               utils.ProcessURL(opts.clientURI),
		AllowUserRegistration:   opts.allowUserRegistration,
		UsernameColumn:          usernameColumn,
		SessionType:             database.SessionTypeSliding,
		AccessTokenTtl:          int32(s.jwt.GetAccessTTL()),
		TokenEndpointAuthMethod: opts.authMethod,
		GrantTypes:              opts.grantTypes,
		LogoUri:                 mapEmptyURL(opts.logoURI),
		TosUri:                  mapEmptyURL(opts.tosURI),
		PolicyUri:               mapEmptyURL(opts.policyURI),
		SoftwareID:              mapEmptyString(opts.softwareID),
		SoftwareVersion:         mapEmptyString(opts.softwareVersion),
		Scopes:                  stdScopes,
		DefaultScopes:           defaultStdScopes,
		CustomScopes:            customScopes,
		DefaultCustomScopes:     defaultCustomScopes,
		Domain:                  derivedDomain,
		ResponseTypes:           opts.responseTypes,
		AuthProviders:           authProviders,
		RedirectUris:            redirectURIs,
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

	authProviders, serviceErr := mapAuthProviders(opts.authProviders)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth providers", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	usernameColumn, serviceErr := mapUsernameColumn(opts.usernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	derivedDomain, serviceErr := mapDomain(opts.clientURI, opts.domain)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map domain", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

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
		CreationMethod:          opts.creationMethod,
		AppType:                 opts.appType,
		ClientName:              opts.name,
		ClientID:                clientID,
		ClientUri:               utils.ProcessURL(opts.clientURI),
		AllowUserRegistration:   opts.allowUserRegistration,
		UsernameColumn:          usernameColumn,
		SessionType:             database.SessionTypeSliding,
		AccessTokenTtl:          int32(s.jwt.GetAccessTTL()),
		TokenEndpointAuthMethod: opts.authMethod,
		GrantTypes:              opts.grantTypes,
		LogoUri:                 mapEmptyURL(opts.logoURI),
		TosUri:                  mapEmptyURL(opts.tosURI),
		PolicyUri:               mapEmptyURL(opts.policyURI),
		SoftwareID:              mapEmptyString(opts.softwareID),
		SoftwareVersion:         mapEmptyString(opts.softwareVersion),
		Scopes:                  stdScopes,
		DefaultScopes:           defaultStdScopes,
		CustomScopes:            customScopes,
		DefaultCustomScopes:     defaultCustomScopes,
		Domain:                  derivedDomain,
		AuthProviders:           authProviders,
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
		return database.App{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App created successfully")
	return app, nil
}

type CreateWebAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	CreationMethod        database.CreationMethod
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
	RedirectURIs          []string
	ResponseTypes         []string
	GrantTypes            []string
	Scopes                []string
	DefaultScopes         []string
	AuthProviders         []string
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

	grantTypes, serviceErr := mapAppGrantTypes(database.AppTypeWeb, opts.GrantTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if serviceErr := validateAppAuthGrantTypes(database.AppTypeWeb, authMethod, grantTypes); serviceErr != nil {
		return dtos.AppDTO{}, serviceErr
	}
	var responseTypes []database.ResponseType
	if slices.Contains(grantTypes, database.GrantTypeAuthorizationCode) {
		responseTypes, serviceErr = mapResponseTypesWithDefault(opts.ResponseTypes)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}
		if len(opts.RedirectURIs) == 0 {
			return dtos.AppDTO{}, exceptions.NewValidationError("redirect URIs are required for authorization_code grant")
		}
	} else {
		if len(opts.ResponseTypes) > 0 {
			return dtos.AppDTO{}, exceptions.NewValidationError("response types are not supported without authorization_code grant")
		}
		responseTypes = make([]database.ResponseType, 0)
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
		requestID:  opts.RequestID,
		accountID:  accountID,
		name:       name,
		softwareID: opts.SoftwareID,
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
		creationMethod:        opts.CreationMethod,
		appType:               database.AppTypeWeb,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		usernameColumn:        opts.UsernameColumn,
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
		redirectURIs:          opts.RedirectURIs,
		responseTypes:         responseTypes,
		authProviders:         opts.AuthProviders,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethod {
	case AuthMethodNone:
		logger.InfoContext(ctx, "Created public web app successfully")
		return dtos.MapAppToDTO(&app), nil
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
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: s.appCCExpDays,
			usage:     database.CredentialsUsageApp,
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

type CreateNativeAppOptions struct {
	RequestID             string
	AccountPublicID       uuid.UUID
	AccountVersion        int32
	AppType               database.AppType
	CreationMethod        database.CreationMethod
	Name                  string
	AllowUserRegistration bool
	Domain                string
	UsernameColumn        string
	ResponseTypes         []string
	ClientURI             string
	LogoURI               string
	TOSURI                string
	PolicyURI             string
	Contacts              []string
	SoftwareID            string
	SoftwareVersion       string
	RedirectURIs          []string
	Scopes                []string
	DefaultScopes         []string
	AuthProviders         []string
}

func (s *Services) CreateNativeApp(
	ctx context.Context,
	opts CreateNativeAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateNativeApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating native app...")

	responseTypes, serviceErr := mapResponseTypesWithDefault(opts.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
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
		requestID:  opts.RequestID,
		accountID:  accountID,
		name:       name,
		softwareID: opts.SoftwareID,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	app, serviceErr := s.createSingleApp(ctx, createAppOptions{
		requestID:             opts.RequestID,
		accountID:             accountID,
		accountPublicID:       opts.AccountPublicID,
		creationMethod:        opts.CreationMethod,
		appType:               opts.AppType,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		domain:                opts.Domain,
		usernameColumn:        opts.UsernameColumn,
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
		redirectURIs:          opts.RedirectURIs,
		responseTypes:         responseTypes,
		authProviders:         opts.AuthProviders,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created native app successfully")
	return dtos.MapAppToDTO(&app), nil
}

func mapUpdateAuthProviders(
	authProviders []string,
	currentAuthProviders []database.AuthProvider,
) ([]database.AuthProvider, *exceptions.ServiceError) {
	if len(authProviders) == 0 {
		return currentAuthProviders, nil
	}

	validAuthProviders := make([]database.AuthProvider, 0, len(authProviders))
	for _, provider := range authProviders {
		dbp := database.AuthProvider(provider)
		switch dbp {
		case database.AuthProviderLocal, database.AuthProviderApple, database.AuthProviderFacebook,
			database.AuthProviderGoogle, database.AuthProviderGithub, database.AuthProviderMicrosoft:
			validAuthProviders = append(validAuthProviders, dbp)
		default:
			return nil, exceptions.NewValidationError("Unsupported auth provider: " + provider)
		}
	}

	return validAuthProviders, nil
}

type updateAppOptions struct {
	requestID             string
	usernameColumn        string
	allowUserRegistration bool
	domain                string
	name                  string
	clientURI             string
	logoURI               string
	tosURI                string
	policyURI             string
	softwareVersion       string
	contacts              []string
	redirectURIs          []string
	responseTypes         []database.ResponseType
	authProviders         []string
}

func (s *Services) updateApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	qrs *database.Queries,
	opts updateAppOptions,
) (database.App, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "updateApp").With(
		"appID", appDTO.ID(),
		"appClientName", appDTO.ClientName,
	)
	logger.InfoContext(ctx, "Updating base app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.usernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	authProviders, serviceErr := mapUpdateAuthProviders(opts.authProviders, appDTO.AuthProviders)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth providers", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	derivedDomain, serviceErr := mapDomain(opts.clientURI, opts.domain)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map domain", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	var softwareVersion pgtype.Text
	if opts.softwareVersion != "" {
		if err := softwareVersion.Scan(opts.softwareVersion); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software version", "error", err)
			return database.App{}, err
		}
	}

	app, err := qrs.UpdateApp(ctx, database.UpdateAppParams{
		ID:                    appDTO.ID(),
		ClientName:            opts.name,
		UsernameColumn:        usernameColumn,
		ClientUri:             opts.clientURI,
		LogoUri:               mapEmptyURL(opts.logoURI),
		TosUri:                mapEmptyURL(opts.tosURI),
		PolicyUri:             mapEmptyURL(opts.policyURI),
		SoftwareVersion:       softwareVersion,
		Domain:                derivedDomain,
		AllowUserRegistration: opts.allowUserRegistration,
		ResponseTypes:         opts.responseTypes,
		AuthProviders:         authProviders,
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
		"appClientName", appDTO.ClientName,
	)
	logger.InfoContext(ctx, "Updating base app...")

	usernameColumn, serviceErr := mapUsernameColumn(opts.usernameColumn)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map username column", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	authProviders, serviceErr := mapUpdateAuthProviders(opts.authProviders, appDTO.AuthProviders)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth providers", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	derivedDomain, serviceErr := mapDomain(opts.clientURI, opts.domain)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map domain", "serviceError", serviceErr)
		return database.App{}, serviceErr
	}

	var softwareVersion pgtype.Text
	if opts.softwareVersion != "" {
		if err := softwareVersion.Scan(opts.softwareVersion); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software version", "error", err)
			return database.App{}, exceptions.NewInternalServerError()
		}
	}

	redirectURIs := opts.redirectURIs
	if redirectURIs == nil {
		redirectURIs = appDTO.RedirectURIs
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	app, err := s.database.UpdateApp(ctx, database.UpdateAppParams{
		ID:                    appDTO.ID(),
		ClientName:            opts.name,
		UsernameColumn:        usernameColumn,
		ClientUri:             opts.clientURI,
		LogoUri:               mapEmptyURL(opts.logoURI),
		TosUri:                mapEmptyURL(opts.tosURI),
		PolicyUri:             mapEmptyURL(opts.policyURI),
		SoftwareVersion:       softwareVersion,
		Domain:                derivedDomain,
		AllowUserRegistration: opts.allowUserRegistration,
		ResponseTypes:         opts.responseTypes,
		AuthProviders:         authProviders,
		Contacts: utils.MapSlice(opts.contacts, func(t *string) string {
			return utils.Lowered(*t)
		}),
		RedirectUris: utils.MapSlice(redirectURIs, func(t *string) string {
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

func mapResponseTypesUpdate(
	responseTypes []string,
	currentResponseTypes []database.ResponseType,
) ([]database.ResponseType, *exceptions.ServiceError) {
	if len(responseTypes) == 0 {
		return currentResponseTypes, nil
	}

	var dbResponseTypes []database.ResponseType
	for _, rt := range responseTypes {
		switch utils.Lowered(rt) {
		case ResponseTypeCode:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeCode)
		case ResponseTypeCodeIdToken:
			dbResponseTypes = append(dbResponseTypes, database.ResponseTypeCodeidToken)
		default:
			return nil, exceptions.NewValidationError("invalid response type: " + rt)
		}
	}

	return dbResponseTypes, nil
}

type UpdateWebNativeAppOptions struct {
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
	RedirectURIs          []string
	ResponseTypes         []string
	AuthProviders         []string
}

// TODO: add related apps
func (s *Services) UpdateWebNativeApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateWebNativeAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateWebNativeApp").With(
		"appID", appDTO.ID(),
		"appClientName", appDTO.ClientName,
		"appType", appDTO.AppType,
	)
	logger.InfoContext(ctx, "Updating web or native app...")

	responseTypes, serviceErr := mapResponseTypesUpdate(opts.ResponseTypes, appDTO.ResponseTypes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map response types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	redirectURIs := opts.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = appDTO.RedirectURIs
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	if len(redirectURIs) == 0 && (slices.Contains(appDTO.GrantTypes, database.GrantTypeAuthorizationCode) ||
		slices.Contains(appDTO.GrantTypes, database.GrantTypeImplicit)) {
		return dtos.AppDTO{}, exceptions.NewValidationError("redirect URIs are required for authorization grants")
	}

	name := strings.TrimSpace(opts.Name)
	if appDTO.ClientName != name {
		if serviceErr := s.checkForDuplicateApps(ctx, checkForDuplicateAppsOptions{
			requestID:  opts.RequestID,
			accountID:  opts.AccountID,
			name:       name,
			softwareID: opts.SoftwareID,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Duplicate app found", "serviceError", serviceErr)
		}
	}

	// Derive domain from client URI when not provided
	domain, serviceErr := mapDomain(opts.ClientURI, opts.Domain)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map domain", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	app, serviceErr := s.updateSingleApp(ctx, appDTO, updateAppOptions{
		requestID:             opts.RequestID,
		usernameColumn:        opts.UsernameColumn,
		domain:                domain,
		name:                  name,
		allowUserRegistration: opts.AllowUserRegistration,
		clientURI:             opts.ClientURI,
		logoURI:               opts.LogoURI,
		tosURI:                opts.TOSURI,
		policyURI:             opts.PolicyURI,
		softwareVersion:       opts.SoftwareVersion,
		contacts:              opts.Contacts,
		redirectURIs:          redirectURIs,
		responseTypes:         responseTypes,
		authProviders:         opts.AuthProviders,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to update app", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated web or native app successfully")
	return dtos.MapAppToDTO(&app), nil
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
	case database.AppTypeWeb, database.AppTypeNative:
		logger.InfoContext(ctx, "Returning app DTO", "appType", app.AppType)
		return dtos.MapAppToDTO(&app), nil
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
	case database.AppTypeNative:
		return nil, 0, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeWeb:
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
	case database.AppTypeNative:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeWeb:
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
	case database.AppTypeNative:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeWeb:
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
		requestID: opts.requestID,
		accountID: opts.accountID,
		expiresIn: s.accountCCExpDays,
		usage:     database.CredentialsUsageApp,
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
	case database.AppTypeNative:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeWeb:
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
