// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"reflect"

	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const oidcConfigLocation string = "oidc_configs"

type CreateOIDCConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Claims          []string
	Scopes          []string
}

func (s *Services) CreateOIDCConfig(
	ctx context.Context,
	opts CreateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "CreateOIDCConfig").With(
		"accountPublicId", opts.AccountPublicID,
	)
	logger.Info("Creating OIDC config...")

	accountDTO, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "serviceErr", serviceErr)
			return dtos.OIDCConfigDTO{}, exceptions.NewUnauthorizedError()
		}

		return dtos.OIDCConfigDTO{}, serviceErr
	}

	count, err := s.database.CountOIDCConfigsByAccountID(ctx, accountDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count user schemas by account id", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.ErrorContext(ctx, "User schema already exists", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewConflictError("User schema already exists")
	}

	encryptedDek, newAccountDEK, err := s.encrypt.GenerateOIDCDEK(ctx, opts.RequestID, accountDTO.DEK())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OIDC StoredDEK", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	if newAccountDEK == "" {
		config, err := s.database.CreateOIDCConfig(ctx, database.CreateOIDCConfigParams{
			AccountID: accountDTO.ID(),
			Claims:    claimsData,
			Scopes:    scopesData,
			Dek:       encryptedDek,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create OIDC config", "error", err)
			return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "OIDC config created successfully")
		return dtos.MapOIDCConfigToDTO(&config)
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	config, err := qrs.CreateOIDCConfig(ctx, database.CreateOIDCConfigParams{
		AccountID: accountDTO.ID(),
		Claims:    claimsData,
		Scopes:    scopesData,
		Dek:       encryptedDek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create OIDC config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	if err := qrs.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		ID:  accountDTO.ID(),
		Dek: newAccountDEK,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "OIDC config created successfully")
	return dtos.MapOIDCConfigToDTO(&config)
}

type GetOIDCConfigByAccountIDOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetOIDCConfigByAccountID(
	ctx context.Context,
	opts GetOIDCConfigByAccountIDOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetOIDCConfigByAccountID").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting OIDC config...")

	config, err := s.database.FindOIDCConfigByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find OIDC config", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "OIDC config found")
	return dtos.MapOIDCConfigToDTO(&config)
}

type createDefaultOIDCConfigOptions struct {
	requestID string
	accountID int32
}

func (s *Services) createDefaultOIDCConfig(
	ctx context.Context,
	opts createDefaultOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oidcConfigLocation, "createDefaultOIDCConfig").With(
		"accountId", opts.accountID,
	)
	logger.InfoContext(ctx, "Creating default OIDC config...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.requestID,
		ID:        opts.accountID,
	})
	if serviceErr != nil {
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	encryptedDek, newAccountDEK, err := s.encrypt.GenerateOIDCDEK(ctx, opts.requestID, accountDTO.DEK())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OIDC StoredDEK", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	if newAccountDEK == "" {
		config, err := s.database.CreateDefaultOIDCConfig(ctx, database.CreateDefaultOIDCConfigParams{
			AccountID: opts.accountID,
			Dek:       encryptedDek,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create default OIDC config", "error", err)
			return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Default OIDC config created successfully")
		return dtos.MapOIDCConfigToDTO(&config)
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	config, err := qrs.CreateDefaultOIDCConfig(ctx, database.CreateDefaultOIDCConfigParams{
		AccountID: opts.accountID,
		Dek:       encryptedDek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create default OIDC config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	if err := qrs.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		Dek: newAccountDEK,
		ID:  opts.accountID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Default OIDC config created successfully")
	return dtos.MapOIDCConfigToDTO(&config)

}

type GetOrCreateOIDCConfigOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetOrCreateOIDCConfig(
	ctx context.Context,
	opts GetOrCreateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetOrCreateOIDCConfig").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating user schema...")

	configDto, serviceErr := s.GetOIDCConfigByAccountID(ctx, GetOIDCConfigByAccountIDOptions(opts))
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get OIDC config", "error", serviceErr)
			return dtos.OIDCConfigDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "OIDC config not found, creating new one")
		return s.createDefaultOIDCConfig(ctx, createDefaultOIDCConfigOptions{
			requestID: opts.RequestID,
			accountID: opts.AccountID,
		})
	}

	logger.InfoContext(ctx, "OIDC config found")
	return configDto, nil
}

type GetOrCreateOIDCConfigByPublicIDOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
}

func (s *Services) GetOrCreateOIDCConfigByPublicID(
	ctx context.Context,
	opts GetOrCreateOIDCConfigByPublicIDOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetOrCreateOIDCConfigByPublicID").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Getting or creating OIDC config...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "serviceErr", serviceErr)
			return dtos.OIDCConfigDTO{}, exceptions.NewUnauthorizedError()
		}

		return dtos.OIDCConfigDTO{}, serviceErr
	}

	return s.GetOrCreateOIDCConfig(ctx, GetOrCreateOIDCConfigOptions{
		RequestID: opts.RequestID,
		AccountID: accountDTO.ID(),
	})
}

type UpdateOIDCConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Claims          []string
	Scopes          []string
}

func (s *Services) UpdateOIDCConfig(
	ctx context.Context,
	opts UpdateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "UpdateOIDCConfig").With(
		"accountPublicId", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Updating OIDC config...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "serviceErr", serviceErr)
			return dtos.OIDCConfigDTO{}, exceptions.NewUnauthorizedError()
		}

		return dtos.OIDCConfigDTO{}, serviceErr
	}

	configDTO, serviceErr := s.GetOIDCConfigByAccountID(ctx, GetOIDCConfigByAccountIDOptions{
		RequestID: opts.RequestID,
		AccountID: accountDTO.ID(),
	})
	if serviceErr != nil {
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	claimsData, err := mapSliceToJsonMap(opts.Claims)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal claims", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	scopesData, err := mapSliceToJsonMap(opts.Scopes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal scopes", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	config, err := s.database.UpdateOIDCConfig(ctx, database.UpdateOIDCConfigParams{
		ID:     configDTO.ID(),
		Claims: claimsData,
		Scopes: scopesData,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update OIDC config", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "OIDC config updated successfully")
	return dtos.MapOIDCConfigToDTO(&config)
}

type GetOIDCConfigUserStructOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetOIDCConfigUserStruct(
	ctx context.Context,
	opts GetOIDCConfigUserStructOptions,
) (reflect.Type, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetUserSchemaStruct").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user schema struct...")

	oidcConfigDTO, serviceErr := s.GetOrCreateOIDCConfig(ctx, GetOrCreateOIDCConfigOptions(opts))
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get OIDC config", "error", serviceErr)
		return nil, serviceErr
	}

	logger.InfoContext(ctx, "User schema struct retrieved successfully")
	return BuildClaimSchema(oidcConfigDTO.Claims), nil
}
