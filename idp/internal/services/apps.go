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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appsLocation string = "apps"

var authCodeAppGrantTypes = []database.GrantType{database.GrantTypeAuthorizationCode, database.GrantTypeRefreshToken}
var deviceGrantTypes = []database.GrantType{
	database.GrantTypeUrnIetfParamsOauthGrantTypeDeviceCode,
	database.GrantTypeRefreshToken,
}
var noneAuthMethod = []database.AuthMethod{database.AuthMethodNone}

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
				Type:            appType,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByTypeAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByTypeAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Type:            appType,
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
			Type:            appType,
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
				Type:            appType,
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          opts.Offset,
				Limit:           opts.Limit,
				Type:            appType,
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
			Type:            appType,
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

func mapWebCodeChallengeMethod(method string) (database.CodeChallengeMethod, *exceptions.ServiceError) {
	switch utils.Lowered(method) {
	case "s256":
		return database.CodeChallengeMethodS256, nil
	case "plain":
		return database.CodeChallengeMethodPlain, nil
	case "":
		return database.CodeChallengeMethodNone, nil
	default:
		return "", exceptions.NewValidationError("Unsupported code challenge method")
	}
}

type createAppOptions struct {
	requestID       string
	accountID       int32
	accountPublicID uuid.UUID
	appType         database.AppType
	name            string
	clientURI       string
	usernameColumn  database.AppUsernameColumn
	authMethods     []database.AuthMethod
	grantTypes      []database.GrantType
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       opts.accountID,
		AccountPublicID: opts.accountPublicID,
		Type:            opts.appType,
		Name:            opts.name,
		ClientID:        clientID,
		ClientUri:       utils.ProcessURL(opts.clientURI),
		UsernameColumn:  opts.usernameColumn,
		AuthMethods:     opts.authMethods,
		GrantTypes:      opts.grantTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return database.App{}, err
	}

	logger.InfoContext(ctx, "App created successfully")
	return app, nil
}

type createAppWithAuthCodeConfigOptions struct {
	requestID           string
	accountID           int32
	accountPublicID     uuid.UUID
	appType             database.AppType
	name                string
	clientURI           string
	usernameColumn      database.AppUsernameColumn
	authMethods         []database.AuthMethod
	grantTypes          []database.GrantType
	codeChallengeMethod database.CodeChallengeMethod
	callbackURIs        []string
	logoutURIs          []string
	allowedOrigins      []string
}

func (s *Services) createAppWithAuthConfig(
	ctx context.Context,
	qrs *database.Queries,
	opts createAppWithAuthCodeConfigOptions,
) (database.App, database.AppAuthCodeConfig, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "createAppWithAuthConfig").With(
		"accountPublicId", opts.accountPublicID,
		"name", opts.name,
		"appType", opts.appType,
	)

	app, err := s.createApp(ctx, qrs, createAppOptions{
		requestID:       opts.requestID,
		accountID:       opts.accountID,
		accountPublicID: opts.accountPublicID,
		appType:         opts.appType,
		name:            opts.name,
		clientURI:       opts.clientURI,
		usernameColumn:  opts.usernameColumn,
		authMethods:     opts.authMethods,
		grantTypes:      opts.grantTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		return database.App{}, database.AppAuthCodeConfig{}, err
	}

	authConfig, err := qrs.CreateAppAuthCodeConfig(ctx, database.CreateAppAuthCodeConfigParams{
		AccountID:           opts.accountID,
		AppID:               app.ID,
		CodeChallengeMethod: opts.codeChallengeMethod,
		CallbackUris: utils.MapSlice(opts.callbackURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		LogoutUris: utils.MapSlice(opts.logoutURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		AllowedOrigins: utils.MapSlice(opts.allowedOrigins, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app callback/logout URIs", "error", err)
		return database.App{}, database.AppAuthCodeConfig{}, err
	}

	logger.InfoContext(ctx, "App with auth code config created successfully")
	return app, authConfig, nil
}

type CreateWebAppOptions struct {
	RequestID           string
	AccountPublicID     uuid.UUID
	AccountVersion      int32
	Name                string
	UsernameColumn      string
	AuthMethods         string
	Algorithm           string
	ClientURI           string
	CallbackURIs        []string
	LogoutURIs          []string
	AllowedOrigins      []string
	CodeChallengeMethod string
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

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	codeChallengeMethod, serviceErr := mapWebCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
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

	app, authConfig, err := s.createAppWithAuthConfig(ctx, qrs, createAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		accountID:           accountID,
		accountPublicID:     opts.AccountPublicID,
		appType:             database.AppTypeWeb,
		name:                name,
		clientURI:           opts.ClientURI,
		usernameColumn:      usernameColumn,
		authMethods:         authMethods,
		grantTypes:          authCodeAppGrantTypes,
		codeChallengeMethod: codeChallengeMethod,
		callbackURIs:        opts.CallbackURIs,
		logoutURIs:          opts.LogoutURIs,
		allowedOrigins:      opts.AllowedOrigins,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethods {
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
		return dtos.MapWebAppWithJWKToDTO(&app, &authConfig, jwk, clientKey.ExpiresAt), nil
	case AuthMethodBothClientSecrets, AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		var dbPrms database.CreateCredentialsSecretParams
		var secret string
		dbPrms, secret, serviceErr = s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: s.accountCCExpDays,
			usage:     database.CredentialsUsageApp,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientSecret database.CredentialsSecret
		clientSecret, err = qrs.CreateCredentialsSecret(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: clientSecret.ID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created web app successfully with client secret auth method successfully")
		return dtos.MapWebAppWithSecretToDTO(
			&app,
			&authConfig,
			clientSecret.SecretID,
			secret,
			clientSecret.ExpiresAt,
		), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethods)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

func mapMandatoryCodeChallengeMethod(method string) (database.CodeChallengeMethod, *exceptions.ServiceError) {
	switch utils.Lowered(method) {
	case "s256":
		return database.CodeChallengeMethodS256, nil
	case "plain":
		return database.CodeChallengeMethodPlain, nil
	default:
		return "", exceptions.NewValidationError("Unsupported code challenge method")
	}
}

type CreateSPAAppOptions struct {
	RequestID           string
	AccountPublicID     uuid.UUID
	AccountVersion      int32
	Name                string
	UsernameColumn      string
	ClientURI           string
	CallbackURIs        []string
	LogoutURIs          []string
	AllowedOrigins      []string
	CodeChallengeMethod string
}

func (s *Services) CreateSPAApp(
	ctx context.Context,
	opts CreateSPAAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateSPAApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating SPA app...")

	codeChallengeMethod, serviceErr := mapMandatoryCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
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

	app, authConfig, err := s.createAppWithAuthConfig(ctx, qrs, createAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		accountID:           accountID,
		accountPublicID:     opts.AccountPublicID,
		appType:             database.AppTypeSpa,
		name:                name,
		clientURI:           opts.ClientURI,
		usernameColumn:      usernameColumn,
		authMethods:         noneAuthMethod,
		grantTypes:          authCodeAppGrantTypes,
		codeChallengeMethod: codeChallengeMethod,
		callbackURIs:        opts.CallbackURIs,
		logoutURIs:          opts.LogoutURIs,
		allowedOrigins:      opts.AllowedOrigins,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created SPA app successfully")
	return dtos.MapSPAAppToDTO(&app, &authConfig), nil
}

type CreateNativeAppOptions struct {
	RequestID           string
	AccountPublicID     uuid.UUID
	AccountVersion      int32
	Name                string
	UsernameColumn      string
	ClientURI           string
	CallbackURIs        []string
	LogoutURIs          []string
	CodeChallengeMethod string
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
	logger.InfoContext(ctx, "Creating Native app...")

	codeChallengeMethod, serviceErr := mapMandatoryCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
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

	app, authConfig, err := s.createAppWithAuthConfig(ctx, qrs, createAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		accountID:           accountID,
		accountPublicID:     opts.AccountPublicID,
		appType:             database.AppTypeNative,
		name:                name,
		clientURI:           opts.ClientURI,
		usernameColumn:      usernameColumn,
		authMethods:         noneAuthMethod,
		grantTypes:          authCodeAppGrantTypes,
		codeChallengeMethod: codeChallengeMethod,
		callbackURIs:        opts.CallbackURIs,
		logoutURIs:          opts.LogoutURIs,
		allowedOrigins:      make([]string, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app and auth config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created Native app successfully")
	return dtos.MapNativeAppToDTO(&app, &authConfig), nil
}

type CreateBackendAppOptions struct {
	RequestID        string
	AccountPublicID  uuid.UUID
	AccountVersion   int32
	Name             string
	UsernameColumn   string
	AuthMethods      string
	Issuers          []string
	Algorithm        string
	ClientURI        string
	ConfirmationURL  string
	ResetPasswordURL string
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

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	grantTypes, serviceErr := mapServiceGrantTypesFromAuthMethods(opts.AuthMethods)
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
		requestID:       opts.RequestID,
		accountID:       accountID,
		accountPublicID: opts.AccountPublicID,
		appType:         database.AppTypeBackend,
		name:            name,
		clientURI:       opts.ClientURI,
		usernameColumn:  usernameColumn,
		authMethods:     authMethods,
		grantTypes:      grantTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	serverConfig, err := qrs.CreateAppServerConfig(ctx, database.CreateAppServerConfigParams{
		AccountID:        accountID,
		AppID:            app.ID,
		ConfirmationUrl:  utils.ProcessURL(opts.ConfirmationURL),
		ResetPasswordUrl: utils.ProcessURL(opts.ResetPasswordURL),
		Issuers: utils.MapSlice(opts.Issuers, func(issuer *string) string {
			return utils.ProcessURL(*issuer)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app server config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethods {
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
		return dtos.MapBackendAppWithJWKToDTO(&app, &serverConfig, jwk, clientKey.ExpiresAt), nil
	case AuthMethodBothClientSecrets, AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		var dbPrms database.CreateCredentialsSecretParams
		var secret string
		dbPrms, secret, serviceErr = s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: s.accountCCExpDays,
			usage:     database.CredentialsUsageApp,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientSecret database.CredentialsSecret
		clientSecret, err = qrs.CreateCredentialsSecret(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: clientSecret.ID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created backend app successfully with client secret auth method successfully")
		return dtos.MapBackendAppWithSecretToDTO(
			&app,
			&serverConfig,
			clientSecret.SecretID,
			secret,
			clientSecret.ExpiresAt,
		), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethods)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

type CreateDeviceAppOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Name            string
	UsernameColumn  string
	ClientURI       string
	BackendDomain   string
	AssociatedApps  []string
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
			AccountID:       accountID,
			AccountPublicID: opts.AccountPublicID,
			Type:            database.AppTypeDevice,
			Name:            name,
			UsernameColumn:  usernameColumn,
			ClientID:        clientID,
			AuthMethods:     noneAuthMethod,
			ClientUri:       clientURI,
			GrantTypes:      deviceGrantTypes,
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
		if ra.Type != database.AppTypeWeb && ra.Type != database.AppTypeSpa {
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
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeDevice,
		Name:            name,
		UsernameColumn:  usernameColumn,
		ClientID:        clientID,
		ClientUri:       clientURI,
		AuthMethods:     noneAuthMethod,
		GrantTypes:      deviceGrantTypes,
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

func mapServiceGrantTypesFromAuthMethods(authMethods string) ([]database.GrantType, *exceptions.ServiceError) {
	switch authMethods {
	case AuthMethodBothClientSecrets, AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		return []database.GrantType{database.GrantTypeClientCredentials}, nil
	case AuthMethodPrivateKeyJwt:
		return []database.GrantType{database.GrantTypeUrnIetfParamsOauthGrantTypeJwtBearer}, nil
	default:
		return nil, exceptions.NewValidationError("Unsupported auth method")
	}
}

type CreateServiceAppOptions struct {
	RequestID        string
	AccountPublicID  uuid.UUID
	Name             string
	AuthMethods      string
	AccountVersion   int32
	Issuers          []string
	Algorithm        string
	ClientURI        string
	UsersAuthMethods string
	AllowedDomains   []string
}

func (s *Services) CreateServiceApp(
	ctx context.Context,
	opts CreateServiceAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "CreateServiceApp").With(
		"accountPublicId", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"name", opts.Name,
		"authMethods", opts.AuthMethods,
	)
	logger.InfoContext(ctx, "Creating service app...")

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if slices.Contains(authMethods, database.AuthMethodPrivateKeyJwt) && len(opts.Issuers) == 0 {
		logger.ErrorContext(ctx, "Allowed domains must be provided for private key JWT auth method")
		return dtos.AppDTO{}, exceptions.NewValidationError("Allowed domains must be provided for private key JWT auth method")
	}

	grantTypes, serviceErr := mapServiceGrantTypesFromAuthMethods(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map service grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}

	userAuthMethods, serviceErr := mapAuthMethod(opts.UsersAuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user auth methods", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if slices.Contains(userAuthMethods, database.AuthMethodPrivateKeyJwt) && len(opts.AllowedDomains) == 0 {
		logger.ErrorContext(ctx, "Allowed domains must be provided for private key JWT auth method")
		return dtos.AppDTO{}, exceptions.NewValidationError("Allowed domains must be provided for private key JWT auth method")
	}

	userGrantTypes, serviceErr := mapServiceGrantTypesFromAuthMethods(opts.UsersAuthMethods)
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
		requestID:       opts.RequestID,
		accountID:       accountID,
		accountPublicID: opts.AccountPublicID,
		appType:         database.AppTypeService,
		name:            name,
		clientURI:       opts.ClientURI,
		usernameColumn:  database.AppUsernameColumnEmail,
		authMethods:     authMethods,
		grantTypes:      grantTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	appService, err := qrs.CreateAppServiceConfig(ctx, database.CreateAppServiceConfigParams{
		AccountID:      accountID,
		AppID:          app.ID,
		AuthMethods:    userAuthMethods,
		GrantTypes:     userGrantTypes,
		AllowedDomains: utils.ToEmptySlice(opts.AllowedDomains),
		Issuers: utils.MapSlice(opts.Issuers, func(issuer *string) string {
			return utils.ProcessURL(*issuer)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app service config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	switch opts.AuthMethods {
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
	case AuthMethodBothClientSecrets, AuthMethodClientSecretPost, AuthMethodClientSecretBasic:
		var dbPrms database.CreateCredentialsSecretParams
		var secret string
		dbPrms, secret, serviceErr = s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: s.accountCCExpDays,
			usage:     database.CredentialsUsageApp,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
			return dtos.AppDTO{}, serviceErr
		}

		var clientSecret database.CredentialsSecret
		clientSecret, err = qrs.CreateCredentialsSecret(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
			AppID:               app.ID,
			CredentialsSecretID: clientSecret.ID,
			AccountID:           accountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AppDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Created service app successfully with client secret auth method successfully")
		return dtos.MapServiceAppWithSecretToDTO(
			&app,
			&appService,
			clientSecret.SecretID,
			secret,
			clientSecret.ExpiresAt,
		), nil
	default:
		logger.ErrorContext(ctx, "Unsupported auth method", "authMethod", opts.AuthMethods)
		serviceErr = exceptions.NewValidationError("Unsupported auth method")
		return dtos.AppDTO{}, serviceErr
	}
}

func buildOptionalURL(url string) (pgtype.Text, error) {
	if url == "" {
		return pgtype.Text{}, nil
	}

	var pgURL pgtype.Text
	if err := pgURL.Scan(utils.ProcessURL(url)); err != nil {
		return pgtype.Text{}, err
	}

	return pgURL, nil
}

type updateAppOptions struct {
	requestID       string
	usernameColumn  database.AppUsernameColumn
	name            string
	clientURI       string
	logoURI         string
	tosURI          string
	policyURI       string
	softwareID      string
	softwareVersion string
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

	logoURI, err := buildOptionalURL(opts.logoURI)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build logo URI", "error", err)
		return database.App{}, err
	}

	tosURI, err := buildOptionalURL(opts.tosURI)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build tos URI", "error", err)
		return database.App{}, err
	}

	policyURI, err := buildOptionalURL(opts.policyURI)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build policy URI", "error", err)
		return database.App{}, err
	}

	var softwareID pgtype.Text
	if opts.softwareID != "" {
		if err := softwareID.Scan(opts.softwareID); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software ID", "error", err)
			return database.App{}, err
		}
	}

	var softwareVersion pgtype.Text
	if opts.softwareVersion != "" {
		if err := softwareVersion.Scan(opts.softwareVersion); err != nil {
			logger.ErrorContext(ctx, "Failed to scan software version", "error", err)
			return database.App{}, err
		}
	}

	app, err := qrs.UpdateApp(ctx, database.UpdateAppParams{
		ID:              appDTO.ID(),
		UsernameColumn:  opts.usernameColumn,
		Name:            opts.name,
		ClientUri:       opts.clientURI,
		LogoUri:         logoURI,
		TosUri:          tosURI,
		PolicyUri:       policyURI,
		SoftwareID:      softwareID,
		SoftwareVersion: softwareVersion,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app", "error", err)
		return database.App{}, err
	}

	logger.InfoContext(ctx, "Updated base app successfully")
	return app, nil
}

type updateAppWithAuthCodeConfigOptions struct {
	requestID           string
	usernameColumn      database.AppUsernameColumn
	name                string
	clientURI           string
	logoURI             string
	tosURI              string
	policyURI           string
	softwareID          string
	softwareVersion     string
	callbackURIs        []string
	logoutURIs          []string
	allowedOrigins      []string
	codeChallengeMethod database.CodeChallengeMethod
}

func (s *Services) updateAppWithAuthCodeConfig(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	qrs *database.Queries,
	opts updateAppWithAuthCodeConfigOptions,
) (database.App, database.AppAuthCodeConfig, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "updateAppWithAuthCodeConfig").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
		"appType", appDTO.Type,
	)
	logger.InfoContext(ctx, "Updating app with auth code config...")

	app, err := s.updateApp(ctx, appDTO, qrs, updateAppOptions{
		requestID:       opts.requestID,
		usernameColumn:  opts.usernameColumn,
		name:            opts.name,
		clientURI:       opts.clientURI,
		logoURI:         opts.logoURI,
		tosURI:          opts.tosURI,
		policyURI:       opts.policyURI,
		softwareID:      opts.softwareID,
		softwareVersion: opts.softwareVersion,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update base app", "error", err)
		return database.App{}, database.AppAuthCodeConfig{}, err
	}

	appAuthCodeConfig, err := qrs.UpdateAppAuthCodeConfig(ctx, database.UpdateAppAuthCodeConfigParams{
		AccountID: app.AccountID,
		AppID:     app.ID,
		CallbackUris: utils.MapSlice(opts.callbackURIs, func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		LogoutUris: utils.MapSlice(opts.logoutURIs, func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		AllowedOrigins: utils.MapSlice(opts.allowedOrigins, func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		CodeChallengeMethod: opts.codeChallengeMethod,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app auth code config", "error", err)
		return database.App{}, database.AppAuthCodeConfig{}, err
	}

	logger.InfoContext(ctx, "Updated app with auth code config successfully")
	return app, appAuthCodeConfig, nil
}

type UpdateWebAppOptions struct {
	RequestID           string
	AccountID           int32
	UsernameColumn      string
	Name                string
	ClientURI           string
	LogoURI             string
	TOSURI              string
	PolicyURI           string
	SoftwareID          string
	SoftwareVersion     string
	CallbackURLs        []string
	LogoutURLs          []string
	AllowedOrigins      []string
	CodeChallengeMethod string
}

func (s *Services) UpdateWebApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateWebAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateWebApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating web app...")

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

	codeChallengeMethod, serviceErr := mapWebCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
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

	app, appAuthCodeConfig, err := s.updateAppWithAuthCodeConfig(ctx, appDTO, qrs, updateAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		usernameColumn:      usernameColumn,
		name:                opts.Name,
		clientURI:           opts.ClientURI,
		logoURI:             opts.LogoURI,
		tosURI:              opts.TOSURI,
		policyURI:           opts.PolicyURI,
		softwareID:          opts.SoftwareID,
		softwareVersion:     opts.SoftwareVersion,
		callbackURIs:        opts.CallbackURLs,
		logoutURIs:          opts.LogoutURLs,
		allowedOrigins:      opts.AllowedOrigins,
		codeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app and auth code config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated web app successfully")
	return dtos.MapWebAppToDTO(&app, &appAuthCodeConfig), nil
}

type UpdateSPAAppOptions struct {
	RequestID           string
	AccountID           int32
	UsernameColumn      string
	Name                string
	ClientURI           string
	LogoURI             string
	TOSURI              string
	PolicyURI           string
	SoftwareID          string
	SoftwareVersion     string
	CallbackURLs        []string
	LogoutURLs          []string
	AllowedOrigins      []string
	CodeChallengeMethod string
}

func (s *Services) UpdateSPAApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateSPAAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateSPAApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating SPA app...")

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

	codeChallengeMethod, serviceErr := mapMandatoryCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
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

	app, appAuthCodeConfig, err := s.updateAppWithAuthCodeConfig(ctx, appDTO, qrs, updateAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		usernameColumn:      usernameColumn,
		name:                opts.Name,
		clientURI:           opts.ClientURI,
		logoURI:             opts.LogoURI,
		tosURI:              opts.TOSURI,
		policyURI:           opts.PolicyURI,
		softwareID:          opts.SoftwareID,
		softwareVersion:     opts.SoftwareVersion,
		callbackURIs:        opts.CallbackURLs,
		logoutURIs:          opts.LogoutURLs,
		allowedOrigins:      opts.AllowedOrigins,
		codeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app and auth code config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated SPA app successfully")
	return dtos.MapSPAAppToDTO(&app, &appAuthCodeConfig), nil
}

type UpdateNativeAppOptions struct {
	RequestID           string
	AccountID           int32
	UsernameColumn      string
	Name                string
	ClientURI           string
	LogoURI             string
	TOSURI              string
	PolicyURI           string
	SoftwareID          string
	SoftwareVersion     string
	CallbackURIs        []string
	LogoutURIs          []string
	CodeChallengeMethod string
}

func (s *Services) UpdateNativeApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	opts UpdateNativeAppOptions,
) (dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appsLocation, "UpdateNativeApp").With(
		"appID", appDTO.ID(),
		"appName", appDTO.Name,
	)
	logger.InfoContext(ctx, "Updating native app...")

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

	codeChallengeMethod, serviceErr := mapMandatoryCodeChallengeMethod(opts.CodeChallengeMethod)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map code challenge method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
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

	app, appAuthCodeConfig, err := s.updateAppWithAuthCodeConfig(ctx, appDTO, qrs, updateAppWithAuthCodeConfigOptions{
		requestID:           opts.RequestID,
		usernameColumn:      usernameColumn,
		name:                opts.Name,
		clientURI:           opts.ClientURI,
		logoURI:             opts.LogoURI,
		tosURI:              opts.TOSURI,
		policyURI:           opts.PolicyURI,
		softwareID:          opts.SoftwareID,
		softwareVersion:     opts.SoftwareVersion,
		callbackURIs:        opts.CallbackURIs,
		logoutURIs:          opts.LogoutURIs,
		allowedOrigins:      make([]string, 0),
		codeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app and auth code config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated native app successfully")
	return dtos.MapNativeAppToDTO(&app, &appAuthCodeConfig), nil
}

type UpdateBackendAppOptions struct {
	RequestID        string
	AccountID        int32
	UsernameColumn   string
	Name             string
	ClientURI        string
	LogoURI          string
	TOSURI           string
	PolicyURI        string
	SoftwareID       string
	SoftwareVersion  string
	ConfirmationURL  string
	ResetPasswordURL string
	Issuers          []string
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

	app, err := s.updateApp(ctx, appDTO, qrs, updateAppOptions{
		requestID:       opts.RequestID,
		usernameColumn:  usernameColumn,
		name:            opts.Name,
		clientURI:       opts.ClientURI,
		logoURI:         opts.LogoURI,
		tosURI:          opts.TOSURI,
		policyURI:       opts.PolicyURI,
		softwareID:      opts.SoftwareID,
		softwareVersion: opts.SoftwareVersion,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update base app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	serverConfig, err := qrs.UpdateAppServerConfig(ctx, database.UpdateAppServerConfigParams{
		AccountID:        app.AccountID,
		AppID:            app.ID,
		ConfirmationUrl:  utils.ProcessURL(opts.ConfirmationURL),
		ResetPasswordUrl: utils.ProcessURL(opts.ResetPasswordURL),
		Issuers: utils.MapSlice(opts.Issuers, func(issuer *string) string {
			return utils.ProcessURL(*issuer)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app server config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated backend app successfully")
	return dtos.MapBackendAppToDTO(&app, &serverConfig), nil
}

type UpdateDeviceAppOptions struct {
	RequestID       string
	AccountID       int32
	UsernameColumn  string
	Name            string
	ClientURI       string
	LogoURI         string
	TOSURI          string
	PolicyURI       string
	SoftwareID      string
	SoftwareVersion string
	BackendDomain   string
	AssociatedApps  []string
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
			if ra.Type != database.AppTypeWeb && ra.Type != database.AppTypeSpa {
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
		requestID:       opts.RequestID,
		usernameColumn:  usernameColumn,
		name:            opts.Name,
		clientURI:       opts.ClientURI,
		logoURI:         opts.LogoURI,
		tosURI:          opts.TOSURI,
		policyURI:       opts.PolicyURI,
		softwareID:      opts.SoftwareID,
		softwareVersion: opts.SoftwareVersion,
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
	RequestID       string
	AccountID       int32
	Name            string
	ClientURI       string
	LogoURI         string
	TOSURI          string
	PolicyURI       string
	SoftwareID      string
	SoftwareVersion string
	AllowedDomains  []string
	Issuers         []string
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
		requestID:       opts.RequestID,
		usernameColumn:  database.AppUsernameColumnEmail, // Service apps always use email
		name:            opts.Name,
		clientURI:       opts.ClientURI,
		logoURI:         opts.LogoURI,
		tosURI:          opts.TOSURI,
		policyURI:       opts.PolicyURI,
		softwareID:      opts.SoftwareID,
		softwareVersion: opts.SoftwareVersion,
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
		Issuers: utils.MapSlice(opts.Issuers, func(issuer *string) string {
			return utils.ProcessURL(*issuer)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app service config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated service app successfully")
	return dtos.MapServiceAppToDTO(&app, &serviceConfig), nil
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

	switch app.Type {
	case database.AppTypeWeb, database.AppTypeSpa, database.AppTypeNative:
		authCodeConfig, err := s.database.FindAppAuthCodeConfig(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find app auth code config", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}

		if app.Type == database.AppTypeWeb {
			logger.InfoContext(ctx, "Found app auth code config for web app")
			return dtos.MapWebAppToDTO(&app, &authCodeConfig), nil
		}
		if app.Type == database.AppTypeSpa {
			logger.InfoContext(ctx, "Found app auth code config for spa app")
			return dtos.MapSPAAppToDTO(&app, &authCodeConfig), nil
		}

		logger.InfoContext(ctx, "Found app auth code config for native app")
		return dtos.MapNativeAppToDTO(&app, &authCodeConfig), nil
	case database.AppTypeBackend:
		serverConfig, err := s.database.FindAppServerConfig(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find app server config", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}
		return dtos.MapBackendAppToDTO(&app, &serverConfig), nil
	case database.AppTypeDevice:
		relatedApps, err := s.database.FindRelatedAppsByAppID(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find related apps", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}
		return dtos.MapDeviceAppToDTO(&app, relatedApps, opts.BackendDomain), nil
	case database.AppTypeService:
		serviceConfig, err := s.database.FindAppServiceConfig(ctx, app.ID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find app service config", "error", err)
			return dtos.AppDTO{}, exceptions.FromDBError(err)
		}
		return dtos.MapServiceAppToDTO(&app, &serviceConfig), nil
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", app.Type)
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
	switch appDTO.Type {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return nil, 0, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService:
		if len(appDTO.AuthMethods) != 1 || appDTO.AuthMethods[0] != database.AuthMethodPrivateKeyJwt {
			return nil, 0, exceptions.NewConflictError("App type does not support secrets or keys")
		}
		return s.listAppKeys(ctx, listAppKeysOptions{
			requestID: opts.RequestID,
			appID:     appDTO.ID(),
			offset:    opts.Offset,
			limit:     opts.Limit,
		})
	case database.AppTypeWeb:
		amHashSet := utils.SliceToHashSet(appDTO.AuthMethods)
		if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
			return s.listAppKeys(ctx, listAppKeysOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				offset:    opts.Offset,
				limit:     opts.Limit,
			})
		}
		if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
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
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.Type)
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

	switch appDTO.Type {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		amHashSet := utils.SliceToHashSet(appDTO.AuthMethods)
		if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
			return s.getAppKeyByID(ctx, getAppKeyByIDOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				publicKID: opts.SecretID,
			})
		}
		if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
			return s.getAppSecretByID(ctx, getAppSecretByIDOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				secretID:  opts.SecretID,
			})
		}

		logger.WarnContext(ctx, "No auth method to get secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to get secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.Type)
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

	switch appDTO.Type {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		amHashSet := utils.SliceToHashSet(appDTO.AuthMethods)
		if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
			return s.revokeAppKey(ctx, revokeAppKeyOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				publicKID: opts.SecretID,
			})
		}
		if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
			return s.revokeAppSecret(ctx, revokeAppSecretOptions{
				requestID: opts.RequestID,
				appID:     appDTO.ID(),
				secretID:  opts.SecretID,
			})
		}

		logger.WarnContext(ctx, "No auth method to revoke secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to revoke secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.Type)
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
	requestID string
	accountID int32
	appID     int32
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

	dbPrms, secret, serviceErr := s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
		requestID: opts.requestID,
		accountID: opts.accountID,
		expiresIn: s.accountCCExpDays,
		usage:     database.CredentialsUsageApp,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	clientSecret, err := qrs.CreateCredentialsSecret(ctx, dbPrms)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	if err = qrs.CreateAppSecret(ctx, database.CreateAppSecretParams{
		AppID:               opts.appID,
		CredentialsSecretID: clientSecret.ID,
		AccountID:           opts.accountID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create app secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App secret rotated successfully")
	return dtos.MapCredentialsSecretToDTOWithSecret(&clientSecret, secret), nil
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

	switch appDTO.Type {
	case database.AppTypeSpa, database.AppTypeNative, database.AppTypeDevice:
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("App type does not support secrets or keys")
	case database.AppTypeBackend, database.AppTypeService, database.AppTypeWeb:
		amHashSet := utils.SliceToHashSet(appDTO.AuthMethods)
		if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
			return s.rotateAppKey(ctx, rotateAppKeyOptions{
				requestID:       opts.RequestID,
				accountID:       accountID,
				accountPublicID: opts.AccountPublicID,
				appID:           appDTO.ID(),
				cryptoSuite:     mapAlgorithmToTokenCryptoSuite(opts.Algorithm),
			})
		}
		if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
			return s.rotateAppSecret(ctx, rotateAppSecretOptions{
				requestID: opts.RequestID,
				accountID: accountID,
				appID:     appDTO.ID(),
			})
		}

		logger.WarnContext(ctx, "No auth method to rotate secret or key")
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to rotate secrets")
	default:
		logger.ErrorContext(ctx, "Invalid app type", "appType", appDTO.Type)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewInternalServerError()
	}
}
