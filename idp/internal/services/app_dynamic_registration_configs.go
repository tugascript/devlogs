// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	appDynamicRegistrationConfigsLocation string = "app_dynamic_registration_configs"

	appDynamicRegistrationConfigCacheTTL time.Duration = 24 * time.Hour
)

func buildAppDynamicRegistrationConfigCacheKey(accountID int32) string {
	return fmt.Sprintf("%s:%d", appDynamicRegistrationConfigsLocation, accountID)
}

func mapAppTypes(appTypes []string) ([]database.AppType, *exceptions.ServiceError) {
	appTypesDB := make([]database.AppType, 0, len(appTypes))
	for _, appType := range appTypes {
		appTypeDB, serviceErr := mapAppTypeToDB(appType)
		if serviceErr != nil {
			return nil, serviceErr
		}
		appTypesDB = append(appTypesDB, appTypeDB)
	}
	return appTypesDB, nil
}

func mapScopes(scopes []string) ([]database.Scopes, *exceptions.ServiceError) {
	scopesDB := make([]database.Scopes, 0, len(scopes))
	for _, scope := range scopes {
		scopeDB, serviceErr := mapScope(scope)
		if serviceErr != nil {
			return nil, serviceErr
		}
		scopesDB = append(scopesDB, scopeDB)
	}
	return scopesDB, nil
}

func mapGrantTypes(grantTypes []string) ([]database.GrantType, *exceptions.ServiceError) {
	grantTypesDB := make([]database.GrantType, 0, len(grantTypes))
	for _, grantType := range grantTypes {
		grantTypeDB, serviceErr := mapGrantType(grantType)
		if serviceErr != nil {
			return nil, serviceErr
		}
		grantTypesDB = append(grantTypesDB, grantTypeDB)
	}
	return grantTypesDB, nil
}

func mapResponseTypes(responseTypes []string) ([]database.ResponseType, *exceptions.ServiceError) {
	var responseTypesDB []database.ResponseType
	for _, responseType := range responseTypes {
		switch utils.Lowered(responseType) {
		case ResponseTypeCode:
			responseTypesDB = append(responseTypesDB, database.ResponseTypeCode)
		case ResponseTypeCodeIdToken:
			responseTypesDB = append(responseTypesDB, database.ResponseTypeCodeidToken)
		default:
			return nil, exceptions.NewValidationError("invalid response type: " + responseType)
		}
	}
	return responseTypesDB, nil
}

func mapAuthMethods(authMethods []string) ([]database.AuthMethod, *exceptions.ServiceError) {
	authMethodsDB := make([]database.AuthMethod, 0, len(authMethods))
	for _, authMethod := range authMethods {
		authMethodDB, serviceErr := mapAuthMethod(authMethod)
		if serviceErr != nil {
			return nil, serviceErr
		}
		authMethodsDB = append(authMethodsDB, authMethodDB)
	}
	return authMethodsDB, nil
}

type SaveAppDynamicRegistrationConfigOptions struct {
	RequestID                            string
	AccountPublicID                      uuid.UUID
	AccountVersion                       int32
	AllowedAppTypes                      []string
	DefaultAllowUserRegistration         bool
	DefaultAuthProviders                 []string
	DefaultUsernameColumn                string
	DefaultAllowedScopes                 []string
	DefaultScopes                        []string
	RequireVerifiedDomainsAppTypes       []string
	RequireSoftwareStatementAppTypes     []string
	SoftwareStatementVerificationMethods []string
	RequireInitialAccessTokenAppTypes    []string
	InitialAccessTokenGenerationMethods  []string
	InitialAccessTokenTtl                int32
	InitialAccessTokenMaxUses            int32
	AllowedGrantTypes                    []string
	AllowedResponseTypes                 []string
	AllowedTokenEndpointAuthMethods      []string
	MaxRedirectUris                      int32
}

func (s *Services) SaveAppDynamicRegistrationConfig(
	ctx context.Context,
	opts SaveAppDynamicRegistrationConfigOptions,
) (dtos.AppDynamicRegistrationConfigDTO, bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationConfigsLocation, "SaveAppDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
	)
	logger.InfoContext(ctx, "Saving app dynamic registration config...")

	allowedAppTypes, serviceErr := mapAppTypes(opts.AllowedAppTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map allowed app types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	defaultAuthProviders, serviceErr := mapAuthProviders(opts.DefaultAuthProviders)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map default auth providers", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	defaultUsernameColumn, serviceErr := mapUsernameColumn(opts.DefaultUsernameColumn)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map default username column", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	defaultAllowedScopes, serviceErr := mapScopes(opts.DefaultAllowedScopes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map default allowed scopes", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	defaultScopes, serviceErr := mapScopes(opts.DefaultScopes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map default scopes", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	requireVerifiedDomainsAppTypes, serviceErr := mapAppTypes(opts.RequireVerifiedDomainsAppTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map require verified domains app types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	requireSoftwareStatementAppTypes, serviceErr := mapAppTypes(opts.RequireSoftwareStatementAppTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map require software statement app types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	softwareStatementVerificationMethods, serviceErr := mapSoftwareStatementVerificationMethods(opts.SoftwareStatementVerificationMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map software statement verification methods", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	requireInitialAccessTokenAppTypes, serviceErr := mapAppTypes(opts.RequireInitialAccessTokenAppTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map require initial access token app types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	initialAccessTokenGenerationMethods, serviceErr := mapInitialAccessTokenGenerationMethods(opts.InitialAccessTokenGenerationMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map initial access token generation methods", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	allowedGrantTypes, serviceErr := mapGrantTypes(opts.AllowedGrantTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map allowed grant types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	allowedResponseTypes, serviceErr := mapResponseTypes(opts.AllowedResponseTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map allowed response types", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	allowedTokenEndpointAuthMethods, serviceErr := mapAuthMethods(opts.AllowedTokenEndpointAuthMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map allowed token endpoint auth methods", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	appDynamicRegistrationConfig, err := s.database.FindAppDynamicRegistrationConfigByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app dynamic registration config", "error", err)
			return dtos.AppDynamicRegistrationConfigDTO{}, false, serviceErr
		}

		logger.InfoContext(ctx, "App dynamic registration config not found, creating new one...")
		appDynamicRegistrationConfig, err = s.database.CreateAppDynamicRegistrationConfig(
			ctx,
			database.CreateAppDynamicRegistrationConfigParams{
				AccountID:                            accountID,
				AccountPublicID:                      opts.AccountPublicID,
				AllowedAppTypes:                      allowedAppTypes,
				DefaultAllowUserRegistration:         opts.DefaultAllowUserRegistration,
				DefaultAuthProviders:                 defaultAuthProviders,
				DefaultUsernameColumn:                defaultUsernameColumn,
				DefaultAllowedScopes:                 defaultAllowedScopes,
				DefaultScopes:                        defaultScopes,
				RequireVerifiedDomainsAppTypes:       requireVerifiedDomainsAppTypes,
				RequireSoftwareStatementAppTypes:     requireSoftwareStatementAppTypes,
				SoftwareStatementVerificationMethods: softwareStatementVerificationMethods,
				RequireInitialAccessTokenAppTypes:    requireInitialAccessTokenAppTypes,
				InitialAccessTokenGenerationMethods:  initialAccessTokenGenerationMethods,
				InitialAccessTokenTtl:                opts.InitialAccessTokenTtl,
				InitialAccessTokenMaxUses:            opts.InitialAccessTokenMaxUses,
				AllowedGrantTypes:                    allowedGrantTypes,
				AllowedResponseTypes:                 allowedResponseTypes,
				AllowedTokenEndpointAuthMethods:      allowedTokenEndpointAuthMethods,
				MaxRedirectUris:                      opts.MaxRedirectUris,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app dynamic registration config", "error", err)
			return dtos.AppDynamicRegistrationConfigDTO{}, false, exceptions.FromDBError(err)
		}

		return dtos.MapAppDynamicRegistrationConfigToDTO(&appDynamicRegistrationConfig), true, nil
	}

	appDynamicRegistrationConfig, err = s.database.UpdateAppDynamicRegistrationConfig(ctx, database.UpdateAppDynamicRegistrationConfigParams{
		ID:                                   appDynamicRegistrationConfig.ID,
		AllowedAppTypes:                      allowedAppTypes,
		DefaultAllowUserRegistration:         opts.DefaultAllowUserRegistration,
		DefaultAuthProviders:                 defaultAuthProviders,
		DefaultUsernameColumn:                defaultUsernameColumn,
		DefaultAllowedScopes:                 defaultAllowedScopes,
		DefaultScopes:                        defaultScopes,
		RequireVerifiedDomainsAppTypes:       requireVerifiedDomainsAppTypes,
		RequireSoftwareStatementAppTypes:     requireSoftwareStatementAppTypes,
		SoftwareStatementVerificationMethods: softwareStatementVerificationMethods,
		RequireInitialAccessTokenAppTypes:    requireInitialAccessTokenAppTypes,
		InitialAccessTokenGenerationMethods:  initialAccessTokenGenerationMethods,
		InitialAccessTokenTtl:                opts.InitialAccessTokenTtl,
		InitialAccessTokenMaxUses:            opts.InitialAccessTokenMaxUses,
		AllowedGrantTypes:                    allowedGrantTypes,
		AllowedResponseTypes:                 allowedResponseTypes,
		AllowedTokenEndpointAuthMethods:      allowedTokenEndpointAuthMethods,
		MaxRedirectUris:                      opts.MaxRedirectUris,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app dynamic registration config", "error", err)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, exceptions.FromDBError(err)
	}

	if err := s.cache.DeleteResponse(ctx, cache.DeleteResponseOptions{
		RequestID: opts.RequestID,
		Key:       buildAppDynamicRegistrationConfigCacheKey(accountID),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to delete cached app dynamic registration config", "error", err)
		return dtos.AppDynamicRegistrationConfigDTO{}, false, exceptions.NewInternalServerError()
	}

	return dtos.MapAppDynamicRegistrationConfigToDTO(&appDynamicRegistrationConfig), false, nil
}

type GetAppDynamicRegistrationConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
}

func (s *Services) GetAppDynamicRegistrationConfig(
	ctx context.Context,
	opts GetAppDynamicRegistrationConfigOptions,
) (dtos.AppDynamicRegistrationConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationConfigsLocation, "GetAppDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Retrieving app dynamic registration config...")

	appDynamicRegistrationConfig, err := s.database.FindAppDynamicRegistrationConfigByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app dynamic registration config", "error", err)
			return dtos.AppDynamicRegistrationConfigDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "App dynamic registration config not found", "error", err)
		return dtos.AppDynamicRegistrationConfigDTO{}, nil
	}

	return dtos.MapAppDynamicRegistrationConfigToDTO(&appDynamicRegistrationConfig), nil
}

type GetAndCacheAppDynamicRegistrationConfigOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetAndCacheAppDynamicRegistrationConfig(
	ctx context.Context,
	opts GetAndCacheAppDynamicRegistrationConfigOptions,
) (dtos.AppDynamicRegistrationConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationConfigsLocation, "GetAndCacheAppDynamicRegistrationConfig").With(
		"accountID", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting and caching app dynamic registration config...")

	appDRConfigDTO, found, err := cache.GetResponseWithoutETag(s.cache, ctx, cache.GetResponseOptions[dtos.AppDynamicRegistrationConfigDTO]{
		RequestID: opts.RequestID,
		Key:       buildAppDynamicRegistrationConfigCacheKey(opts.AccountID),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get cached app dynamic registration config", "error", err)
		return dtos.AppDynamicRegistrationConfigDTO{}, exceptions.NewInternalServerError()
	}
	if found {
		logger.InfoContext(ctx, "App dynamic registration config found in cache")
		return appDRConfigDTO, nil
	}

	appDRConfig, err := s.database.FindAppDynamicRegistrationConfigByAccountID(ctx, opts.AccountID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app dynamic registration config", "error", err)
			return dtos.AppDynamicRegistrationConfigDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "App dynamic registration config not found, creating new one...")
		return dtos.AppDynamicRegistrationConfigDTO{}, exceptions.NewNotFoundError()
	}

	appDRConfigDTO = dtos.MapAppDynamicRegistrationConfigToDTO(&appDRConfig)
	if err := cache.SaveResponseWithoutETag(s.cache, ctx, cache.SaveResponseOptions[dtos.AppDynamicRegistrationConfigDTO]{
		RequestID: opts.RequestID,
		Key:       buildAppDynamicRegistrationConfigCacheKey(opts.AccountID),
		TTL:       appDynamicRegistrationConfigCacheTTL,
		Value:     appDRConfigDTO,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to save app dynamic registration config to cache", "error", err)
		return dtos.AppDynamicRegistrationConfigDTO{}, exceptions.NewInternalServerError()
	}

	return appDRConfigDTO, nil
}

type DeleteAppDynamicRegistrationConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
}

func (s *Services) DeleteAppDynamicRegistrationConfig(
	ctx context.Context,
	opts DeleteAppDynamicRegistrationConfigOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationConfigsLocation, "DeleteAppDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
	)
	logger.InfoContext(ctx, "Deleting app dynamic registration config...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
		return serviceErr
	}

	appDynamicRegistrationConfig, serviceErr := s.GetAppDynamicRegistrationConfig(
		ctx,
		GetAppDynamicRegistrationConfigOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: accountDTO.PublicID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app dynamic registration config", "serviceError", serviceErr)
		return serviceErr
	}

	if err := s.database.DeleteAppDynamicRegistrationConfig(ctx, appDynamicRegistrationConfig.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete app dynamic registration config", "error", err)
		return exceptions.FromDBError(err)
	}

	return nil
}
