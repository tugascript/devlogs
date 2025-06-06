// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func isBuiltInProvider(provider string) bool {
	builtInProviders := []string{
		AuthProviderUsernamePassword,
		AuthProviderApple,
		AuthProviderFacebook,
		AuthProviderGitHub,
		AuthProviderGoogle,
		AuthProviderMicrosoft,
	}
	return slices.Contains(builtInProviders, provider)
}

type CreateExternalAuthProviderOptions struct {
	RequestID    string
	AccountID    int32
	Name         string
	Icon         string
	ClientID     string
	ClientSecret string
	Scopes       []string
	AuthURL      string
	TokenURL     string
	UserInfoURL  string
	EmailKey     string
	UserMapping  map[string]string
}

func (s *Services) CreateExternalAuthProvider(
	ctx context.Context,
	opts CreateExternalAuthProviderOptions,
) (dtos.ExternalAuthProviderDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "CreateExternalAuthProvider").With(
		"accountId", opts.AccountID,
		"name", opts.Name,
	)
	logger.InfoContext(ctx, "Creating external auth Provider...")

	// Validate Provider name doesn't conflict with built-in providers
	name := utils.Capitalized(opts.Name)
	provider := utils.Slugify(name)
	if isBuiltInProvider(name) {
		logger.WarnContext(ctx, "Provider name conflicts with built-in Provider", "Provider", provider)
		return dtos.ExternalAuthProviderDTO{}, exceptions.NewValidationError(
			fmt.Sprintf("Provider name '%s' conflicts with built-in Provider", name),
		)
	}

	// Create external auth Provider
	userSchemaJSON, err := json.Marshal(opts.UserSchema)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user schema", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	userMappingJSON, err := json.Marshal(opts.UserMapping)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal user mapping", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "accountId", opts.AccountID)
			return dtos.ExternalAuthProviderDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Error getting account", "error", serviceErr)
		return dtos.ExternalAuthProviderDTO{}, serviceErr
	}

	encryptedSecret, newDEK, err := s.encrypt.EncryptWithAccountDEK(ctx, encryption.EncryptWithAccountDEKOptions{
		RequestID: opts.RequestID,
		StoredDEK: accountDTO.DEK(),
		Text:      opts.ClientSecret,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt client secret", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	if newDEK != "" {
		qrs, txn, err := s.database.BeginTx(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
			return dtos.ExternalAuthProviderDTO{}, exceptions.FromDBError(err)
		}
		defer func() {
			logger.DebugContext(ctx, "Finalizing transaction")
			s.database.FinalizeTx(ctx, txn, err, serviceErr)
		}()

		authProvider, err := qrs.CreateExternalAuthProvider(ctx, database.CreateExternalAuthProviderParams{
			Name:         name,
			Provider:     provider,
			Icon:         opts.Icon,
			AccountID:    opts.AccountID,
			ClientID:     opts.ClientID,
			ClientSecret: encryptedSecret,
			Scopes:       opts.Scopes,
			AuthUrl:      opts.AuthURL,
			TokenUrl:     opts.TokenURL,
			UserInfoUrl:  opts.UserInfoURL,
			EmailKey:     opts.EmailKey,
			UserSchema:   userSchemaJSON,
			UserMapping:  userMappingJSON,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create external auth Provider", "error", err)
			return dtos.ExternalAuthProviderDTO{}, exceptions.FromDBError(err)
		}

		if err := s.database.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
			Dek: newDEK,
			ID:  opts.AccountID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.ExternalAuthProviderDTO{}, exceptions.NewServerError()
		}

		return dtos.MapExternalAuthProviderWithSecretToDTO(&authProvider, opts.ClientSecret)
	}

	authProvider, err := s.database.CreateExternalAuthProvider(ctx, database.CreateExternalAuthProviderParams{
		Name:         name,
		Provider:     provider,
		Icon:         opts.Icon,
		AccountID:    opts.AccountID,
		ClientID:     opts.ClientID,
		ClientSecret: encryptedSecret,
		Scopes:       opts.Scopes,
		AuthUrl:      opts.AuthURL,
		TokenUrl:     opts.TokenURL,
		UserInfoUrl:  opts.UserInfoURL,
		EmailKey:     opts.EmailKey,
		UserSchema:   userSchemaJSON,
		UserMapping:  userMappingJSON,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create external auth Provider", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "External auth Provider created successfully", "providerId", authProvider.ID)
	return dtos.MapExternalAuthProviderWithSecretToDTO(&authProvider, opts.ClientSecret)
}

type GetExternalAuthProviderByIDOptions struct {
	RequestID string
	AccountID int32
	ID        int32
}

func (s *Services) GetExternalAuthProviderByID(
	ctx context.Context,
	opts GetExternalAuthProviderByIDOptions,
) (dtos.ExternalAuthProviderDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "GetExternalAuthProvider").With(
		"accountId", opts.AccountID,
		"externalAuthProviderId", opts.ID,
	)
	logger.InfoContext(ctx, "Getting external auth Provider...")

	provider, err := s.database.FindExternalAuthProviderByID(ctx, opts.ID)
	if err != nil {
		logger.WarnContext(ctx, "Failed to get external auth Provider", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.FromDBError(err)
	}
	if provider.AccountID != opts.AccountID {
		logger.WarnContext(ctx, "External auth Provider not found for account", "accountId", opts.AccountID)
		return dtos.ExternalAuthProviderDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "External auth Provider retrieved successfully")
	return dtos.MapExternalAuthProviderToDTO(&provider)
}

type GetExternalAuthProviderByProviderOptions struct {
	RequestID string
	AccountID int32
	Provider  string
}

func (s *Services) GetExternalAuthProviderByProvider(
	ctx context.Context,
	opts GetExternalAuthProviderByProviderOptions,
) (dtos.ExternalAuthProviderDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "GetExternalAuthProviderByProvider").With(
		"accountId", opts.AccountID,
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Getting external auth providers by Provider...")

	authProvider, err := s.database.FindExternalAuthProviderByProviderAndAccountID(
		ctx,
		database.FindExternalAuthProviderByProviderAndAccountIDParams{
			AccountID: opts.AccountID,
			Provider:  utils.Slugify(opts.Provider),
		},
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to get external auth Provider", "error", err)
		return dtos.ExternalAuthProviderDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "External auth Provider retrieved successfully", "providerId", authProvider.ID)
	return dtos.MapExternalAuthProviderToDTO(&authProvider)
}
