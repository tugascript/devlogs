// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"reflect"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const oidcConfigLocation string = "oidc_configs"

type CreateOIDCConfigOptions struct {
	RequestID      string
	AccountID      int32
	Claims         []string
	Scopes         []string
	JwtCryptoSuite tokens.SupportedCryptoSuite
}

func (s *Services) CreateOIDCConfig(
	ctx context.Context,
	opts CreateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "CreateOIDCConfig").With(
		"accountId", opts.AccountID,
	)
	logger.Info("Creating OIDC config...")

	count, err := s.database.CountOIDCConfigsByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count user schemas by account id", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.ErrorContext(ctx, "User schema already exists", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewConflictError("User schema already exists")
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	encryptedDek, newAccountDEK, err := s.encrypt.GenerateOIDCDEK(ctx, opts.RequestID, accountDTO.DEK())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OIDC StoredDEK", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
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

	if newAccountDEK == "" {
		config, err := s.database.CreateOIDCConfig(ctx, database.CreateOIDCConfigParams{
			AccountID:      opts.AccountID,
			Claims:         claimsData,
			Scopes:         scopesData,
			JwtCryptoSuite: string(opts.JwtCryptoSuite),
			Dek:            encryptedDek,
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
		AccountID:      opts.AccountID,
		Claims:         claimsData,
		Scopes:         scopesData,
		JwtCryptoSuite: string(opts.JwtCryptoSuite),
		Dek:            encryptedDek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create OIDC config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	if err := qrs.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		ID:  opts.AccountID,
		Dek: newAccountDEK,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "OIDC config created successfully")
	return dtos.MapOIDCConfigToDTO(&config)
}

type GetOrCreateOIDCConfigOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetOIDCConfigByAccountID(
	ctx context.Context,
	opts GetOrCreateOIDCConfigOptions,
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

func (s *Services) createDefaultOIDCConfig(
	ctx context.Context,
	opts GetOrCreateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "createDefaultOIDCConfig").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Creating default OIDC config...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	encryptedDek, newAccountDEK, err := s.encrypt.GenerateOIDCDEK(ctx, opts.RequestID, accountDTO.DEK())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OIDC StoredDEK", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	if newAccountDEK == "" {
		config, err := s.database.CreateDefaultOIDCConfig(ctx, database.CreateDefaultOIDCConfigParams{
			AccountID: opts.AccountID,
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
		AccountID: opts.AccountID,
		Dek:       encryptedDek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create default OIDC config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	if err := qrs.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		Dek: newAccountDEK,
		ID:  opts.AccountID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Default OIDC config created successfully")
	return dtos.MapOIDCConfigToDTO(&config)

}

func (s *Services) GetOrCreateOIDCConfig(
	ctx context.Context,
	opts GetOrCreateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetOrCreateOIDCConfig").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating user schema...")

	configDto, serviceErr := s.GetOIDCConfigByAccountID(ctx, opts)
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get OIDC config", "error", serviceErr)
			return dtos.OIDCConfigDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "OIDC config not found, creating new one")
		return s.createDefaultOIDCConfig(ctx, opts)
	}

	logger.InfoContext(ctx, "OIDC config found")
	return configDto, nil
}

type UpdateOIDCConfigOptions struct {
	RequestID      string
	AccountID      int32
	Claims         []string
	Scopes         []string
	JwtCryptoSuite tokens.SupportedCryptoSuite
}

func (s *Services) UpdateOIDCConfig(
	ctx context.Context,
	opts UpdateOIDCConfigOptions,
) (dtos.OIDCConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "UpdateOIDCConfig").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating OIDC config...")

	configDTO, serviceErr := s.GetOIDCConfigByAccountID(ctx, GetOrCreateOIDCConfigOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		return dtos.OIDCConfigDTO{}, serviceErr
	}

	claimsData, err := mapSliceToJsonMap(opts.Claims)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal claims", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.NewServerError()
	}

	config, err := s.database.UpdateOIDCConfig(ctx, database.UpdateOIDCConfigParams{
		ID:     configDTO.ID(),
		Claims: claimsData,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update OIDC config", "error", err)
		return dtos.OIDCConfigDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "OIDC config updated successfully")
	return dtos.MapOIDCConfigToDTO(&config)
}

func (s *Services) GetOIDCConfigUserStruct(
	ctx context.Context,
	opts GetOrCreateOIDCConfigOptions,
) (reflect.Type, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oidcConfigLocation, "GetUserSchemaStruct").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting user schema struct...")

	oidcConfigDTO, serviceErr := s.GetOrCreateOIDCConfig(ctx, opts)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get OIDC config", "error", serviceErr)
		return nil, serviceErr
	}

	logger.InfoContext(ctx, "User schema struct retrieved successfully")
	return BuildClaimSchema(oidcConfigDTO.Claims), nil
}
