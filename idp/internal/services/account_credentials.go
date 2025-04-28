// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsLocation string = "account_keys"

	accountSecretBytes int = 32
)

func mapAndEncodeAccountScopes(
	logger *slog.Logger,
	ctx context.Context,
	scopes []tokens.AccountScope,
) ([]byte, *exceptions.ServiceError) {
	scopesMap := make(map[string]bool)
	for _, s := range scopes {
		scopesMap[s] = true
	}

	scopesJson, err := json.Marshal(scopesMap)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal the scopes map", "error", err)
		return nil, exceptions.NewServerError()
	}

	return scopesJson, nil
}

type CreateAccountCredentialsOptions struct {
	RequestID string
	AccountID int32
	Alias     string
	Scopes    []tokens.AccountScope
}

func (s *Services) CreateAccountCredentials(
	ctx context.Context,
	opts CreateAccountCredentialsOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "CreateAccountCredentials").With(
		"accountId", opts.AccountID,
		"scopes", opts.Scopes,
	)
	logger.InfoContext(ctx, "Creating account keys...")

	alias := utils.Lowered(opts.Alias)
	count, err := s.database.CountAccountCredentialsByAliasAndAccountID(
		ctx,
		database.CountAccountCredentialsByAliasAndAccountIDParams{
			AccountID: opts.AccountID,
			Alias:     alias,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account keys by alias", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}
	if count > 0 {
		logger.WarnContext(ctx, "Account keys alias already exists", "alias", alias)
		return dtos.AccountCredentialsDTO{}, exceptions.NewConflictError("Account keys alias already exists")
	}

	clientID, err := utils.Base62UUID()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client id", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	clientSecret, err := utils.GenerateBase64Secret(accountSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash client secret", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	scopesJson, serviceErr := mapAndEncodeAccountScopes(logger, ctx, opts.Scopes)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	accountCredentials, err := s.database.CreateAccountCredentials(ctx, database.CreateAccountCredentialsParams{
		ClientID:     clientID,
		ClientSecret: hashedSecret,
		AccountID:    opts.AccountID,
		Scopes:       scopesJson,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account keys", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account keys created successfully")
	return dtos.MapAccountCredentialsToDTOWithSecret(&accountCredentials, clientSecret)
}

type GetAccountCredentialsByClientIDOptions struct {
	RequestID string
	ClientID  string
}

func (s *Services) GetAccountCredentialsByClientID(
	ctx context.Context,
	opts GetAccountCredentialsByClientIDOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "GetAccountCredentialsByClientID").With(
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Getting account keys by client id...")

	accountCredentials, err := s.database.FindAccountCredentialsByClientID(ctx, opts.ClientID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account keys not found", "error", err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account keys", "error", err)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account keys by client id successfully")
	return dtos.MapAccountCredentialsToDTO(&accountCredentials)
}

type GetAccountCredentialsByClientIDAndAccountIDOptions struct {
	RequestID string
	AccountID int32
	ClientID  string
}

func (s *Services) GetAccountCredentialsByClientIDAndAccountID(
	ctx context.Context,
	opts GetAccountCredentialsByClientIDAndAccountIDOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "GetAccountCredentialsByClientIDAndAccountID").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting account keys by client id and account id...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientID(ctx, GetAccountCredentialsByClientIDOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
	})
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	akAccountID := accountCredentialsDTO.AccountID()
	if akAccountID != int(opts.AccountID) {
		logger.WarnContext(ctx, "Account keys is not owned by the account",
			"accountCredentialsAccountId", akAccountID,
		)
		return dtos.AccountCredentialsDTO{}, exceptions.NewNotFoundError()
	}

	logger.InfoContext(ctx, "Got account keys by client id and account id successfully")
	return accountCredentialsDTO, nil
}

type ListAccountKeyByAccountID struct {
	RequestID string
	AccountID int
	Offset    int
	Limit     int
}

func (s *Services) ListAccountCredentialsByAccountID(
	ctx context.Context,
	opts ListAccountKeyByAccountID,
) ([]dtos.AccountCredentialsDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "ListAccountCredentialsByAccountID").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Listing account keys by account id...")

	accountID := int32(opts.AccountID)
	accountCredentials, err := s.database.FindPaginatedAccountCredentialsByAccountID(
		ctx,
		database.FindPaginatedAccountCredentialsByAccountIDParams{
			AccountID: accountID,
			Offset:    int32(opts.Offset),
			Limit:     int32(opts.Limit),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to list account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	count, err := s.database.CountAccountCredentialsByAccountID(ctx, accountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	accountCredentialsDTOs, serviceErr := utils.MapSliceWithErr(accountCredentials, dtos.MapAccountCredentialsToDTO)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account keys to DTOs", "error", serviceErr)
		return nil, 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Successfully listed account keys by account id")
	return accountCredentialsDTOs, count, nil
}

type UpdateAccountCredentialsSecretOptions struct {
	RequestID string
	AccountID int32
	ClientID  string
}

func (s *Services) UpdateAccountCredentialsSecret(
	ctx context.Context,
	opts UpdateAccountCredentialsSecretOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "UpdateAccountCredentialsSecret").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Updating account keys secret...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientIDAndAccountID(
		ctx,
		GetAccountCredentialsByClientIDAndAccountIDOptions(opts),
	)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	clientSecret, err := utils.GenerateBase64Secret(accountSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate client secret", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	hashedSecret, err := utils.HashString(clientSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash client secret", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	accountCredentials, err := s.database.UpdateAccountCredentialsClientSecret(ctx, database.UpdateAccountCredentialsClientSecretParams{
		ClientSecret: hashedSecret,
		ClientID:     accountCredentialsDTO.ClientID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account keys secret", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Successfully updated account keys secret")
	return dtos.MapAccountCredentialsToDTOWithSecret(&accountCredentials, clientSecret)
}

type UpdateAccountCredentialsScopesOptions struct {
	RequestID string
	AccountID int32
	ClientID  string
	Alias     string
	Scopes    []tokens.AccountScope
}

func (s *Services) UpdateAccountCredentials(
	ctx context.Context,
	opts UpdateAccountCredentialsScopesOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "UpdateAccountCredentialsScopes").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
		"scopes", opts.Scopes,
	)
	logger.InfoContext(ctx, "Updating account keys scopes...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientIDAndAccountID(
		ctx,
		GetAccountCredentialsByClientIDAndAccountIDOptions{
			RequestID: opts.RequestID,
			AccountID: opts.AccountID,
			ClientID:  opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	scopesJson, serviceErr := mapAndEncodeAccountScopes(logger, ctx, opts.Scopes)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	alias := utils.Lowered(opts.Alias)
	if alias != accountCredentialsDTO.Alias {
		count, err := s.database.CountAccountCredentialsByAliasAndAccountID(
			ctx,
			database.CountAccountCredentialsByAliasAndAccountIDParams{
				AccountID: opts.AccountID,
				Alias:     alias,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to count account keys by alias", "error", err)
			return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
		}
		if count > 0 {
			logger.WarnContext(ctx, "Account keys alias already exists", "alias", alias)
			return dtos.AccountCredentialsDTO{}, exceptions.NewConflictError("Account keys alias already exists")
		}
	}

	accountCredentials, err := s.database.UpdateAccountCredentials(ctx, database.UpdateAccountCredentialsParams{
		ID:     int32(accountCredentialsDTO.ID()),
		Scopes: scopesJson,
		Alias:  alias,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account keys scopes", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapAccountCredentialsToDTO(&accountCredentials)
}

type DeleteAccountCredentialsOptions struct {
	RequestID string
	AccountID int32
	ClientID  string
}

func (s *Services) DeleteAccountCredentials(ctx context.Context, opts DeleteAccountCredentialsOptions) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "DeleteAccountCredentials").With(
		"clientId", opts.ClientID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Deleting account keys...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientIDAndAccountID(
		ctx,
		GetAccountCredentialsByClientIDAndAccountIDOptions(opts),
	)
	if serviceErr != nil {
		return serviceErr
	}

	if err := s.database.DeleteAccountCredentials(ctx, accountCredentialsDTO.ClientID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account keys", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Successfully deleted account keys")
	return nil
}
