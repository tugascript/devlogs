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

const (
	accountDynamicRegistrationConfigsLocation string = "account_dynamic_registration_configs"

	softwareStatementVerificationMethodJwksUri string = "jwks_uri"
	softwareStatementVerificationMethodManual  string = "manual"

	initialAccessTokenGenerationMethodAuthorizationCode string = "authorization_code"
	initialAccessTokenGenerationMethodManual            string = "manual"
)

func mapAccountCredentialsTypes(credentialsTypes []string) ([]database.AccountCredentialsType, *exceptions.ServiceError) {
	accountCredentialsTypes := make([]database.AccountCredentialsType, 0, len(credentialsTypes))
	for _, credentialsType := range credentialsTypes {
		accountCredentialsType, serviceErr := mapAccountCredentialsType(credentialsType)
		if serviceErr != nil {
			return nil, serviceErr
		}
		accountCredentialsTypes = append(accountCredentialsTypes, accountCredentialsType)
	}
	return accountCredentialsTypes, nil
}

func mapSoftwareStatementVerificationMethod(
	softwareStatementVerificationMethod string,
) (database.SoftwareStatementVerificationMethod, *exceptions.ServiceError) {
	switch softwareStatementVerificationMethod {
	case softwareStatementVerificationMethodJwksUri:
		return database.SoftwareStatementVerificationMethodJwksUri, nil
	case softwareStatementVerificationMethodManual:
		return database.SoftwareStatementVerificationMethodManual, nil
	default:
		return "", exceptions.NewValidationError("Invalid software statement verification method: " + softwareStatementVerificationMethod)
	}
}

func mapSoftwareStatementVerificationMethods(
	ssvms []string,
) ([]database.SoftwareStatementVerificationMethod, *exceptions.ServiceError) {
	softwareStatementVerificationMethods := make([]database.SoftwareStatementVerificationMethod, 0, len(ssvms))
	for _, ssvm := range ssvms {
		softwareStatementVerificationMethod, serviceErr := mapSoftwareStatementVerificationMethod(ssvm)
		if serviceErr != nil {
			return nil, serviceErr
		}
		softwareStatementVerificationMethods = append(softwareStatementVerificationMethods, softwareStatementVerificationMethod)
	}
	return softwareStatementVerificationMethods, nil
}

func mapInitialAccessTokenGenerationMethod(
	initialAccessTokenGenerationMethod string,
) (database.InitialAccessTokenGenerationMethod, *exceptions.ServiceError) {
	switch initialAccessTokenGenerationMethod {
	case initialAccessTokenGenerationMethodAuthorizationCode:
		return database.InitialAccessTokenGenerationMethodAuthorizationCode, nil
	case initialAccessTokenGenerationMethodManual:
		return database.InitialAccessTokenGenerationMethodManual, nil
	default:
		return "", exceptions.NewValidationError("Invalid initial access token generation method: " + initialAccessTokenGenerationMethod)
	}
}

func mapInitialAccessTokenGenerationMethods(
	iatgms []string,
) ([]database.InitialAccessTokenGenerationMethod, *exceptions.ServiceError) {
	initialAccessTokenGenerationMethods := make([]database.InitialAccessTokenGenerationMethod, 0, len(iatgms))
	for _, iatgm := range iatgms {
		initialAccessTokenGenerationMethod, serviceErr := mapInitialAccessTokenGenerationMethod(iatgm)
		if serviceErr != nil {
			return nil, serviceErr
		}
		initialAccessTokenGenerationMethods = append(initialAccessTokenGenerationMethods, initialAccessTokenGenerationMethod)
	}
	return initialAccessTokenGenerationMethods, nil
}

type SaveAccountDynamicRegistrationConfigOptions struct {
	RequestID                                string
	AccountPublicID                          uuid.UUID
	AccountVersion                           int32
	AccountCredentialsTypes                  []string
	WhitelistedDomains                       []string
	RequireSoftwareStatementCredentialTypes  []string
	SoftwareStatementVerificationMethods     []string
	RequireInitialAccessTokenCredentialTypes []string
	InitialAccessTokenGenerationMethods      []string
}

func (s *Services) SaveAccountDynamicRegistrationConfig(
	ctx context.Context,
	opts SaveAccountDynamicRegistrationConfigOptions,
) (dtos.AccountDynamicRegistrationConfigDTO, bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountDynamicRegistrationConfigsLocation, "CreateAccountDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
	)
	logger.InfoContext(ctx, "Creating account dynamic registration config...")

	credentialsTypes, serviceErr := mapAccountCredentialsTypes(opts.AccountCredentialsTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map credentials types", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	requireSoftwareStatementCredentialTypes, serviceErr := mapAccountCredentialsTypes(opts.RequireSoftwareStatementCredentialTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map require software statement credential types", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	requireInitialAccessTokenCredentialTypes, serviceErr := mapAccountCredentialsTypes(opts.RequireInitialAccessTokenCredentialTypes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map require initial access token credential types", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	softwareStatementVerificationMethods, serviceErr := mapSoftwareStatementVerificationMethods(opts.SoftwareStatementVerificationMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map software statement verification methods", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	initialAccessTokenGenerationMethods, serviceErr := mapInitialAccessTokenGenerationMethods(opts.InitialAccessTokenGenerationMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map initial access token generation methods", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
	}

	accountDynamicRegistrationConfig, err := s.database.FindAccountDynamicRegistrationConfigByAccountID(ctx, accountID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration config", "error", err)
			return dtos.AccountDynamicRegistrationConfigDTO{}, false, serviceErr
		}

		logger.InfoContext(ctx, "Account dynamic registration config not found, creating new one...")
		accountDynamicRegistrationConfig, err = s.database.CreateAccountDynamicRegistrationConfig(
			ctx,
			database.CreateAccountDynamicRegistrationConfigParams{
				AccountID:                                accountID,
				AccountPublicID:                          opts.AccountPublicID,
				AccountCredentialsTypes:                  credentialsTypes,
				WhitelistedDomains:                       utils.ToEmptySlice(opts.WhitelistedDomains),
				RequireSoftwareStatementCredentialTypes:  requireSoftwareStatementCredentialTypes,
				SoftwareStatementVerificationMethods:     softwareStatementVerificationMethods,
				RequireInitialAccessTokenCredentialTypes: requireInitialAccessTokenCredentialTypes,
				InitialAccessTokenGenerationMethods:      initialAccessTokenGenerationMethods,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create account dynamic registration config", "error", err)
			return dtos.AccountDynamicRegistrationConfigDTO{}, false, exceptions.FromDBError(err)
		}

		return dtos.MapAccountDynamicRegistrationConfigToDTO(&accountDynamicRegistrationConfig), true, nil

	}

	accountDynamicRegistrationConfig, err = s.database.UpdateAccountDynamicRegistrationConfig(ctx, database.UpdateAccountDynamicRegistrationConfigParams{
		ID:                                       accountDynamicRegistrationConfig.ID,
		AccountCredentialsTypes:                  credentialsTypes,
		WhitelistedDomains:                       utils.ToEmptySlice(opts.WhitelistedDomains),
		RequireSoftwareStatementCredentialTypes:  requireSoftwareStatementCredentialTypes,
		SoftwareStatementVerificationMethods:     softwareStatementVerificationMethods,
		RequireInitialAccessTokenCredentialTypes: requireInitialAccessTokenCredentialTypes,
		InitialAccessTokenGenerationMethods:      initialAccessTokenGenerationMethods,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account dynamic registration config", "error", err)
		return dtos.AccountDynamicRegistrationConfigDTO{}, false, exceptions.FromDBError(err)
	}

	return dtos.MapAccountDynamicRegistrationConfigToDTO(&accountDynamicRegistrationConfig), false, nil
}

type GetAccountDynamicRegistrationConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
}

func (s *Services) GetAccountDynamicRegistrationConfig(
	ctx context.Context,
	opts GetAccountDynamicRegistrationConfigOptions,
) (dtos.AccountDynamicRegistrationConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountDynamicRegistrationConfigsLocation, "GetAccountDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Retrieving account dynamic registration config...")

	accountDynamicRegistrationConfig, err := s.database.FindAccountDynamicRegistrationConfigByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration config", "error", err)
			return dtos.AccountDynamicRegistrationConfigDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Account dynamic registration config not found", "error", err)
		return dtos.AccountDynamicRegistrationConfigDTO{}, nil
	}

	return dtos.MapAccountDynamicRegistrationConfigToDTO(&accountDynamicRegistrationConfig), nil
}

type DeleteAccountDynamicRegistrationConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
}

func (s *Services) DeleteAccountDynamicRegistrationConfig(
	ctx context.Context,
	opts DeleteAccountDynamicRegistrationConfigOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountDynamicRegistrationConfigsLocation, "DeleteAccountDynamicRegistrationConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
	)
	logger.InfoContext(ctx, "Deleting account dynamic registration config...")

	dynamicRegistratioDTO, serviceErr := s.GetAccountDynamicRegistrationConfig(
		ctx,
		GetAccountDynamicRegistrationConfigOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account dynamic registration config", "serviceError", serviceErr)
		return serviceErr
	}

	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return serviceErr
	}

	if err := s.database.DeleteAccountDynamicRegistrationConfig(ctx, dynamicRegistratioDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account dynamic registration config", "error", err)
		return exceptions.FromDBError(err)
	}

	return nil
}
