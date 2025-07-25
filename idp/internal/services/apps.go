// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

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

	order := utils.Lowered(opts.Order)
	var apps []database.App
	var err error

	switch order {
	case "date":
		apps, err = s.database.FindPaginatedAppsByAccountPublicIDOrderedByID(ctx,
			database.FindPaginatedAppsByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Offset:          int32(opts.Offset),
				Limit:           int32(opts.Limit),
			},
		)
	case "name":
		apps, err = s.database.FindPaginatedAppsByAccountPublicIDOrderedByName(ctx,
			database.FindPaginatedAppsByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Offset:          int32(opts.Offset),
				Limit:           int32(opts.Limit),
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
				Offset:          int32(opts.Offset),
				Limit:           int32(opts.Limit),
			},
		)
	case "name":
		apps, err = s.database.FilterAppsByNameAndByAccountPublicIDOrderedByName(ctx,
			database.FilterAppsByNameAndByAccountPublicIDOrderedByNameParams{
				AccountPublicID: opts.AccountPublicID,
				Name:            name,
				Offset:          int32(opts.Offset),
				Limit:           int32(opts.Limit),
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

	name := utils.Capitalized(opts.Name)
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeWeb,
		Name:            name,
		UsernameColumn:  usernameColumn,
		ClientID:        clientID,
		AuthMethods:     authMethods,
		GrantTypes:      authCodeAppGrantTypes,
		ClientUri:       utils.ProcessURL(opts.ClientURI),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	authConfig, err := qrs.CreateAppAuthCodeConfig(ctx, database.CreateAppAuthCodeConfigParams{
		AccountID:           accountID,
		AppID:               app.ID,
		CodeChallengeMethod: codeChallengeMethod,
		CallbackUris: utils.MapSlice(opts.CallbackURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		LogoutUris: utils.MapSlice(opts.LogoutURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		AllowedOrigins: utils.MapSlice(opts.AllowedOrigins, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app callback/logout URIs", "error", err)
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

	name := utils.Capitalized(opts.Name)
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeSpa,
		Name:            name,
		UsernameColumn:  usernameColumn,
		ClientID:        clientID,
		AuthMethods:     noneAuthMethod,
		GrantTypes:      authCodeAppGrantTypes,
		ClientUri:       utils.ProcessURL(opts.ClientURI),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	authConfig, err := qrs.CreateAppAuthCodeConfig(ctx, database.CreateAppAuthCodeConfigParams{
		AccountID:           accountID,
		AppID:               app.ID,
		CodeChallengeMethod: codeChallengeMethod,
		CallbackUris: utils.MapSlice(opts.CallbackURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		LogoutUris: utils.MapSlice(opts.LogoutURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		AllowedOrigins: utils.MapSlice(opts.AllowedOrigins, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app callback/logout URIs", "error", err)
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

	name := utils.Capitalized(opts.Name)
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeNative,
		Name:            name,
		UsernameColumn:  usernameColumn,
		ClientID:        clientID,
		ClientUri:       utils.ProcessURL(opts.ClientURI),
		AuthMethods:     noneAuthMethod,
		GrantTypes:      authCodeAppGrantTypes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	authConfig, err := qrs.CreateAppAuthCodeConfig(ctx, database.CreateAppAuthCodeConfigParams{
		AccountID:           accountID,
		AppID:               app.ID,
		CodeChallengeMethod: codeChallengeMethod,
		CallbackUris: utils.MapSlice(opts.CallbackURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		LogoutUris: utils.MapSlice(opts.LogoutURIs, func(uri *string) string {
			return utils.ProcessURL(*uri)
		}),
		AllowedOrigins: make([]string, 0),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app callback/logout URIs", "error", err)
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
	logger.InfoContext(ctx, "Creating web app...")

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth method", "serviceError", serviceErr)
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

	name := utils.Capitalized(opts.Name)
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeBackend,
		Name:            name,
		UsernameColumn:  usernameColumn,
		ClientID:        clientID,
		ClientUri:       utils.ProcessURL(opts.ClientURI),
		AuthMethods:     authMethods,
		GrantTypes:      authCodeAppGrantTypes,
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

		logger.InfoContext(ctx, "Created web app successfully with private key JWT auth method successfully")
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

		logger.InfoContext(ctx, "Created web app successfully with client secret auth method successfully")
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

	name := utils.Capitalized(opts.Name)
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
	AccountVersion   int32
	AuthMethods      string
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
	)
	logger.InfoContext(ctx, "Creating service app...")

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth method", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
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

	userGrantTypes, serviceErr := mapServiceGrantTypesFromAuthMethods(opts.UsersAuthMethods)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map user grant types", "serviceError", serviceErr)
		return dtos.AppDTO{}, serviceErr
	}
	if opts.UsersAuthMethods == AuthMethodPrivateKeyJwt && len(opts.AllowedDomains) == 0 {
		logger.ErrorContext(ctx, "Allowed domains must be provided for private key JWT auth method")
		return dtos.AppDTO{}, exceptions.NewValidationError("Allowed domains must be provided for private key JWT auth method")
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

	name := utils.Capitalized(opts.Name)
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

	clientID := utils.Base62UUID()
	app, err := qrs.CreateApp(ctx, database.CreateAppParams{
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Type:            database.AppTypeService,
		Name:            name,
		UsernameColumn:  database.AppUsernameColumnEmail,
		ClientID:        clientID,
		AuthMethods:     authMethods,
		GrantTypes:      grantTypes,
		ClientUri:       utils.ProcessURL(opts.ClientURI),
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

		logger.InfoContext(ctx, "Created service app successfully with private key JWT auth method")
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

		logger.InfoContext(ctx, "Created service app successfully with client secret auth method")
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

type updateBaseAppOptions struct {
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

func (s *Services) updateBaseApp(
	ctx context.Context,
	appDTO *dtos.AppDTO,
	qrs *database.Queries,
	opts updateBaseAppOptions,
) (database.App, error) {
	logger := s.buildLogger(opts.requestID, appsLocation, "updateBaseApp").With(
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

	name := utils.Capitalized(opts.Name)
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

	app, err := s.updateBaseApp(ctx, appDTO, qrs, updateBaseAppOptions{
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

	appAuthCodeConfig, err := qrs.UpdateAppAuthCodeConfig(ctx, database.UpdateAppAuthCodeConfigParams{
		AccountID: app.AccountID,
		AppID:     app.ID,
		CallbackUris: utils.MapSlice(utils.ToEmptySlice(opts.CallbackURLs), func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		LogoutUris: utils.MapSlice(utils.ToEmptySlice(opts.LogoutURLs), func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		AllowedOrigins: utils.MapSlice(utils.ToEmptySlice(opts.AllowedOrigins), func(s *string) string {
			return utils.ProcessURL(*s)
		}),
		CodeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app auth code config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AppDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated web app successfully")
	return dtos.MapWebAppToDTO(&app, &appAuthCodeConfig), nil
}
