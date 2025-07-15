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
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsLocation string = "account_keys"

	accountSecretBytes int = 32

	accountCredentialsSecretExpiry time.Duration = time.Hour * 24 * 365 // 1 year
	accountCredentialsSecretPrefix string        = "acc"

	accountCredentialsKeysCacheTTL       int    = 900 // 15 minutes
	accountCredentialsKeysCacheKeyPrefix string = "account_credentials_keys"
)

func mapAccountCredentialsScope(scope string) (database.AccountCredentialsScope, *exceptions.ServiceError) {
	acScope := database.AccountCredentialsScope(scope)
	switch acScope {
	case database.AccountCredentialsScopeAccountAdmin, database.AccountCredentialsScopeAccountAuthProvidersRead,
		database.AccountCredentialsScopeAccountUsersRead, database.AccountCredentialsScopeAccountUsersWrite,
		database.AccountCredentialsScopeAccountAppsRead, database.AccountCredentialsScopeAccountAppsWrite,
		database.AccountCredentialsScopeAccountCredentialsRead, database.AccountCredentialsScopeAccountCredentialsWrite:
		return acScope, nil
	}

	return "", exceptions.NewValidationError("invalid scope: " + scope)
}

// NOTE: using a map will lead to a null pointer dereference even if the slice is not empty
func mapAccountCredentialsScopes(scopes []string) ([]database.AccountCredentialsScope, *exceptions.ServiceError) {
	scopesSet := utils.MapSliceToHashSet(scopes)
	if scopesSet.IsEmpty() {
		return nil, exceptions.NewValidationError("scopes cannot be empty")
	}

	// return utils.MapSliceWithErr(scopesSet.Items(), mapAccountCredentialsScope)
	mappedScopes := make([]database.AccountCredentialsScope, 0, scopesSet.Size())
	for _, scope := range scopesSet.Items() {
		mappedScope, serviceErr := mapAccountCredentialsScope(scope)
		if serviceErr != nil {
			return nil, serviceErr
		}
		mappedScopes = append(mappedScopes, mappedScope)
	}
	return mappedScopes, nil
}

type CreateAccountCredentialsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Alias           string
	Scopes          []string
	AuthMethods     string
}

func (s *Services) CreateAccountCredentials(
	ctx context.Context,
	opts CreateAccountCredentialsOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "CreateAccountCredentials").With(
		"accountPublicID", opts.AccountPublicID,
		"scopes", opts.Scopes,
		"authMethods", opts.AuthMethods,
	)
	logger.InfoContext(ctx, "Creating account keys...")

	authMethods, serviceErr := mapAuthMethod(opts.AuthMethods)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map auth method", "error", serviceErr, "authMethods", opts.AuthMethods)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	scopes, serviceErr := mapAccountCredentialsScopes(opts.Scopes)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map scopes", "error", serviceErr, "scopes", opts.Scopes)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account id", "error", serviceErr)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	alias := utils.Lowered(opts.Alias)
	count, err := s.database.CountAccountCredentialsByAliasAndAccountID(
		ctx,
		database.CountAccountCredentialsByAliasAndAccountIDParams{
			AccountID: accountID,
			Alias:     alias,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account credentials by alias", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}
	if count > 0 {
		logger.WarnContext(ctx, "Account credentials alias already exists", "alias", alias)
		return dtos.AccountCredentialsDTO{}, exceptions.NewConflictError("Account credentials alias already exists")
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	accountCredentials, err := qrs.CreateAccountCredentials(ctx, database.CreateAccountCredentialsParams{
		ClientID:        utils.Base62UUID(),
		AccountID:       accountID,
		AccountPublicID: opts.AccountPublicID,
		Scopes:          scopes,
		AuthMethods:     authMethods,
		Alias:           alias,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account credentials", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	switch opts.AuthMethods {
	case AuthMethodPrivateKeyJwt:
		dbPrms, jwk, serviceErr := s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: accountCredentialsSecretExpiry,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		clientKey, err := qrs.CreateCredentialsKey(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		if err = qrs.CreateAccountCredentialKey(ctx, database.CreateAccountCredentialKeyParams{
			AccountID:            accountID,
			AccountCredentialsID: accountCredentials.ID,
			CredentialsKeyID:     clientKey.ID,
			AccountPublicID:      opts.AccountPublicID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account credential key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		return dtos.MapAccountCredentialsToDTOWithJWK(&accountCredentials, &jwk, dbPrms.ExpiresAt), nil
	case AuthMethodClientSecretBasic, AuthMethodClientSecretPost, AuthMethodBothClientSecrets:
		dbPrms, secret, serviceErr := s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
			requestID: opts.RequestID,
			accountID: accountID,
			expiresIn: accountCredentialsSecretExpiry,
			prefix:    accountCredentialsSecretPrefix,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		clientSecret, err := qrs.CreateCredentialsSecret(ctx, dbPrms)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		if err = qrs.CreateAccountCredentialSecret(ctx, database.CreateAccountCredentialSecretParams{
			AccountID:            accountID,
			AccountCredentialsID: accountCredentials.ID,
			CredentialsSecretID:  clientSecret.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account credential secret", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AccountCredentialsDTO{}, serviceErr
		}

		return dtos.MapAccountCredentialsToDTOWithSecret(&accountCredentials, clientSecret.SecretID, secret, dbPrms.ExpiresAt), nil
	default:
		logger.ErrorContext(ctx, "Invalid auth method", "authMethods", opts.AuthMethods)
		return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
	}
}

type GetAccountCredentialsByClientIDOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
}

func (s *Services) GetAccountCredentialsByClientID(
	ctx context.Context,
	opts GetAccountCredentialsByClientIDOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "GetAccountCredentialsByClientID").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Getting account keys by client id...")

	accountCredentials, err := s.database.FindAccountCredentialsByAccountPublicIDAndClientID(
		ctx,
		database.FindAccountCredentialsByAccountPublicIDAndClientIDParams{
			AccountPublicID: opts.AccountPublicID,
			ClientID:        opts.ClientID,
		},
	)
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
	return dtos.MapAccountCredentialsToDTO(&accountCredentials), nil
}

type getAccountCredentialsForMutationOptions struct {
	requestID       string
	accountPublicID uuid.UUID
	accountVersion  int32
	clientID        string
}

func (s *Services) getAccountCredentialsForMutation(
	ctx context.Context,
	opts getAccountCredentialsForMutationOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "getAccountCredentialsForMutation").With(
		"clientId", opts.clientID,
		"accountPublicID", opts.accountPublicID,
		"accountVersion", opts.accountVersion,
	)
	logger.InfoContext(ctx, "Getting account keys for mutation...")

	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.requestID,
		PublicID:  opts.accountPublicID,
		Version:   opts.accountVersion,
	}); serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	return s.GetAccountCredentialsByClientID(ctx, GetAccountCredentialsByClientIDOptions{
		RequestID:       opts.requestID,
		AccountPublicID: opts.accountPublicID,
		ClientID:        opts.clientID,
	})
}

type ListAccountCredentialsByAccountPublicID struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int
	Limit           int
}

func (s *Services) ListAccountCredentialsByAccountPublicID(
	ctx context.Context,
	opts ListAccountCredentialsByAccountPublicID,
) ([]dtos.AccountCredentialsDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "ListAccountCredentialsByAccountPublicID").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Listing account keys by account public id...")

	accountCredentials, err := s.database.FindPaginatedAccountCredentialsByAccountPublicID(
		ctx,
		database.FindPaginatedAccountCredentialsByAccountPublicIDParams{
			AccountPublicID: opts.AccountPublicID,
			Offset:          int32(opts.Offset),
			Limit:           int32(opts.Limit),
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to list account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	count, err := s.database.CountAccountCredentialsByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Successfully listed account keys by account id")
	return utils.MapSlice(accountCredentials, dtos.MapAccountCredentialsToDTO), count, nil
}

type UpdateAccountCredentialsScopesOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	ClientID        string
	Alias           string
	Scopes          []tokens.AccountScope
}

func (s *Services) UpdateAccountCredentials(
	ctx context.Context,
	opts UpdateAccountCredentialsScopesOptions,
) (dtos.AccountCredentialsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "UpdateAccountCredentialsScopes").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
		"scopes", opts.Scopes,
	)
	logger.InfoContext(ctx, "Updating account keys scopes...")

	accountCredentialsDTO, serviceErr := s.getAccountCredentialsForMutation(
		ctx,
		getAccountCredentialsForMutationOptions{
			requestID:       opts.RequestID,
			accountPublicID: opts.AccountPublicID,
			accountVersion:  opts.AccountVersion,
			clientID:        opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	scopes, serviceErr := mapAccountCredentialsScopes(opts.Scopes)
	if serviceErr != nil {
		return dtos.AccountCredentialsDTO{}, serviceErr
	}

	alias := utils.Lowered(opts.Alias)
	if alias != accountCredentialsDTO.Alias {
		count, err := s.database.CountAccountCredentialsByAliasAndAccountID(
			ctx,
			database.CountAccountCredentialsByAliasAndAccountIDParams{
				AccountID: accountCredentialsDTO.AccountID(),
				Alias:     alias,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to count account credentials by alias", "error", err)
			return dtos.AccountCredentialsDTO{}, exceptions.NewServerError()
		}
		if count > 0 {
			logger.WarnContext(ctx, "Account credentials alias already exists", "alias", alias)
			return dtos.AccountCredentialsDTO{}, exceptions.NewConflictError("Account credentials alias already exists")
		}
	}

	accountCredentials, err := s.database.UpdateAccountCredentials(ctx, database.UpdateAccountCredentialsParams{
		ID:     accountCredentialsDTO.ID(),
		Scopes: scopes,
		Alias:  alias,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account keys scopes", "error", err)
		return dtos.AccountCredentialsDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapAccountCredentialsToDTO(&accountCredentials), nil
}

type DeleteAccountCredentialsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	ClientID        string
}

func (s *Services) DeleteAccountCredentials(ctx context.Context, opts DeleteAccountCredentialsOptions) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "DeleteAccountCredentials").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Deleting account keys...")

	accountCredentialsDTO, serviceErr := s.getAccountCredentialsForMutation(
		ctx,
		getAccountCredentialsForMutationOptions{
			requestID:       opts.RequestID,
			accountPublicID: opts.AccountPublicID,
			accountVersion:  opts.AccountVersion,
			clientID:        opts.ClientID,
		},
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

type createAccountCredentialsKeyOptions struct {
	requestID            string
	accountID            int32
	accountPublicID      uuid.UUID
	accountCredentialsID int32
}

func (s *Services) createAccountCredentialsKey(
	ctx context.Context,
	opts createAccountCredentialsKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "createAccountCredentialsKey").With(
		"AccountID", opts.accountID,
		"accountCredentialsID", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Creating account credentials key...")

	dbPrms, jwk, serviceErr := s.clientCredentialsKey(ctx, clientCredentialsKeyOptions{
		requestID: opts.requestID,
		accountID: opts.accountID,
		expiresIn: accountCredentialsSecretExpiry,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	clientKey, err := qrs.CreateCredentialsKey(ctx, dbPrms)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create client key", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	if err = qrs.CreateAccountCredentialKey(ctx, database.CreateAccountCredentialKeyParams{
		AccountID:            opts.accountID,
		AccountCredentialsID: opts.accountCredentialsID,
		CredentialsKeyID:     clientKey.ID,
		AccountPublicID:      opts.accountPublicID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create account credential key", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	return dtos.MapCredentialsKeyToDTOWithJWK(&clientKey, &jwk), nil
}

type rotateAccountCredentialsKeyOptions struct {
	requestID            string
	accountID            int32
	accountPublicID      uuid.UUID
	accountCredentialsID int32
}

func (s *Services) rotateAccountCredentialsKey(
	ctx context.Context,
	opts rotateAccountCredentialsKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "rotateAccountCredentialsKey").With(
		"accountId", opts.accountID,
		"accountCredentialsId", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Rotating account credentials key...")

	currentKey, err := s.database.FindCurrentAccountCredentialKeyByAccountCredentialID(
		ctx,
		opts.accountID,
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find current account credentials key")
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		return s.createAccountCredentialsKey(ctx, createAccountCredentialsKeyOptions(opts))
	}

	if isMoreThanHalfExpiry(currentKey.CreatedAt, currentKey.ExpiresAt) {
		logger.InfoContext(ctx, "Current account credentials key is more than half expired, creating a new one")
		return s.createAccountCredentialsKey(ctx, createAccountCredentialsKeyOptions(opts))
	}

	logger.WarnContext(ctx, "Current account credentials key is not more than half expired, returning it")
	return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("Current account credentials key is not more than half expired")
}

type createAccountCredentialsSecretOptions struct {
	requestID            string
	accountID            int32
	accountCredentialsID int32
}

func (s *Services) createAccountCredentialsSecret(
	ctx context.Context,
	opts createAccountCredentialsSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "createAccountCredentialsSecret").With(
		"AccountID", opts.accountID,
		"accountCredentialsID", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Creating account credentials secret...")

	dbPrms, secret, serviceErr := s.clientCredentialsSecret(ctx, clientCredentialsSecretOptions{
		requestID: opts.requestID,
		accountID: opts.accountID,
		expiresIn: accountCredentialsSecretExpiry,
		prefix:    accountCredentialsSecretPrefix,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate client credentials secret", "serviceError", serviceErr)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	clientSecret, err := qrs.CreateCredentialsSecret(ctx, dbPrms)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create client secret", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	if err = qrs.CreateAccountCredentialSecret(ctx, database.CreateAccountCredentialSecretParams{
		AccountID:            opts.accountID,
		AccountCredentialsID: opts.accountCredentialsID,
		CredentialsSecretID:  clientSecret.ID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create account credential secret", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	return dtos.MapCredentialsSecretToDTOWithSecret(&clientSecret, secret), nil
}

type rotateAccountCredentialsSecretOptions struct {
	requestID            string
	accountID            int32
	accountCredentialsID int32
}

func (s *Services) rotateAccountCredentialsSecret(
	ctx context.Context,
	opts rotateAccountCredentialsSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "rotateAccountCredentialsSecret").With(
		"AccountID", opts.accountID,
		"accountCredentialsID", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Rotating account credentials secret...")

	currentSecret, err := s.database.FindCurrentAccountCredentialSecretByAccountCredentialID(
		ctx,
		opts.accountID,
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find current account credentials secret")
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		return s.createAccountCredentialsSecret(ctx, createAccountCredentialsSecretOptions(opts))
	}

	if isMoreThanHalfExpiry(currentSecret.CreatedAt, currentSecret.ExpiresAt) {
		logger.InfoContext(ctx, "Current account credentials secret is more than half expired, creating a new one")
		return s.createAccountCredentialsSecret(ctx, createAccountCredentialsSecretOptions(opts))
	}

	logger.WarnContext(ctx, "Current account credentials secret is not more than half expired, returning it")
	return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("Current account credentials secret is not more than half expired")
}

type RotateAccountCredentialsSecretOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	ClientID        string
}

func (s *Services) RotateAccountCredentialsSecret(
	ctx context.Context,
	opts RotateAccountCredentialsSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "RotateAccountCredentialsSecret").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Rotating account keys secret...")

	accountCredentialsDTO, serviceErr := s.getAccountCredentialsForMutation(
		ctx,
		getAccountCredentialsForMutationOptions{
			requestID:       opts.RequestID,
			accountPublicID: opts.AccountPublicID,
			accountVersion:  opts.AccountVersion,
			clientID:        opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	amHashSet := utils.MapSliceToHashSet(accountCredentialsDTO.AuthMethods)
	if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
		return s.rotateAccountCredentialsKey(ctx, rotateAccountCredentialsKeyOptions{
			requestID:            opts.RequestID,
			accountID:            accountCredentialsDTO.AccountID(),
			accountPublicID:      opts.AccountPublicID,
			accountCredentialsID: accountCredentialsDTO.ID(),
		})
	}
	if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
		return s.rotateAccountCredentialsSecret(ctx, rotateAccountCredentialsSecretOptions{
			requestID:            opts.RequestID,
			accountID:            accountCredentialsDTO.AccountID(),
			accountCredentialsID: accountCredentialsDTO.ID(),
		})
	}

	logger.WarnContext(ctx, "No auth method to rotate secret or key")
	return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to rotate secret")
}

type listAccountCredentialsKeysOptions struct {
	requestID            string
	accountCredentialsID int32
	offset               int32
	limit                int32
}

func (s *Services) listAccountCredentialsKeys(
	ctx context.Context,
	opts listAccountCredentialsKeysOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "listAccountCredentialsKeys").With(
		"accountCredentialsID", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Listing account credentials keys...")

	keys, err := s.database.FindPaginatedAccountCredentialKeysByAccountCredentialID(
		ctx,
		database.FindPaginatedAccountCredentialKeysByAccountCredentialIDParams{
			AccountCredentialsID: opts.accountCredentialsID,
			Offset:               opts.offset,
			Limit:                opts.limit,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find account credentials keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	count, err := s.database.CountAccountCredentialKeysByAccountCredentialID(
		ctx,
		opts.accountCredentialsID,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account credentials keys", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	return utils.MapSlice(keys, dtos.MapCredentialsKeyToDTO), count, nil
}

type listAccountCredentialsSecretsOptions struct {
	requestID            string
	accountCredentialsID int32
	offset               int32
	limit                int32
}

func (s *Services) listAccountCredentialsSecrets(
	ctx context.Context,
	opts listAccountCredentialsSecretsOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "listAccountCredentialsSecrets").With(
		"accountCredentialsID", opts.accountCredentialsID,
	)
	logger.InfoContext(ctx, "Listing account credentials secrets...")

	secrets, err := s.database.FindPaginatedAccountCredentialSecretsByAccountCredentialID(
		ctx,
		database.FindPaginatedAccountCredentialSecretsByAccountCredentialIDParams{
			AccountCredentialsID: opts.accountCredentialsID,
			Offset:               opts.offset,
			Limit:                opts.limit,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find account credentials secrets", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	count, err := s.database.CountAccountCredentialSecretsByAccountCredentialID(
		ctx,
		opts.accountCredentialsID,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account credentials secrets", "error", err)
		return nil, 0, exceptions.NewServerError()
	}

	return utils.MapSlice(secrets, dtos.MapCredentialsSecretToDTO), count, nil
}

type ListAccountCredentialsSecretsOrKeysOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
	Offset          int32
	Limit           int32
}

func (s *Services) ListAccountCredentialsSecretsOrKeys(
	ctx context.Context,
	opts ListAccountCredentialsSecretsOrKeysOptions,
) ([]dtos.ClientCredentialsSecretDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "ListAccountCredentialsSecretsOrKeys").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Listing account credentials secrets or keys...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientID(
		ctx,
		GetAccountCredentialsByClientIDOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
			ClientID:        opts.ClientID,
		},
	)
	if serviceErr != nil {
		return nil, 0, serviceErr
	}

	amHashSet := utils.MapSliceToHashSet(accountCredentialsDTO.AuthMethods)
	if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
		return s.listAccountCredentialsKeys(ctx, listAccountCredentialsKeysOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			offset:               opts.Offset,
			limit:                opts.Limit,
		})
	}
	if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
		return s.listAccountCredentialsSecrets(ctx, listAccountCredentialsSecretsOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			offset:               opts.Offset,
			limit:                opts.Limit,
		})
	}

	logger.WarnContext(ctx, "No auth method to list secrets or keys")
	return nil, 0, exceptions.NewConflictError("No auth method to list secrets")
}

type getAccountCredentialsKeyByIDOptions struct {
	requestID            string
	accountCredentialsID int32
	publicKID            string
}

func (s *Services) getAccountCredentialsKeyByID(
	ctx context.Context,
	opts getAccountCredentialsKeyByIDOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "findAccountCredentialsKeyByID").With(
		"accountCredentialsID", opts.accountCredentialsID,
		"publicKID", opts.publicKID,
	)
	logger.InfoContext(ctx, "Finding account credentials secret by ID...")

	secret, err := s.database.FindAccountCredentialKeyByAccountCredentialIDAndPublicKID(
		ctx,
		database.FindAccountCredentialKeyByAccountCredentialIDAndPublicKIDParams{
			AccountCredentialsID: opts.accountCredentialsID,
			PublicKid:            opts.publicKID,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account credentials key not found", "error", err)
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to find account credentials key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewNotFoundError()
	}

	return dtos.MapCredentialsKeyToDTO(&secret), nil
}

type getAccountCredentialsSecretByIDOptions struct {
	requestID            string
	accountCredentialsID int32
	secretID             string
}

func (s *Services) getAccountCredentialsSecretByID(
	ctx context.Context,
	opts getAccountCredentialsSecretByIDOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "findAccountCredentialsSecretByID").With(
		"accountCredentialsID", opts.accountCredentialsID,
		"secretID", opts.secretID,
	)
	logger.InfoContext(ctx, "Finding account credentials secret by ID...")

	secret, err := s.database.FindAccountCredentialSecretByAccountCredentialIDAndCredentialsSecretID(
		ctx,
		database.FindAccountCredentialSecretByAccountCredentialIDAndCredentialsSecretIDParams{
			AccountCredentialsID: opts.accountCredentialsID,
			SecretID:             opts.secretID,
		},
	)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account credentials secret not found", "error", err)
			return dtos.ClientCredentialsSecretDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to find account credentials secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.NewNotFoundError()
	}

	return dtos.MapCredentialsSecretToDTO(&secret), nil
}

type GetAccountCredentialsSecretOrKeyOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
	SecretID        string
}

func (s *Services) GetAccountCredentialsSecretOrKey(
	ctx context.Context,
	opts GetAccountCredentialsSecretOrKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "GetAccountCredentialsSecretOrKey").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
		"secretID", opts.SecretID,
	)
	logger.InfoContext(ctx, "Getting account credentials secret or key...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientID(
		ctx,
		GetAccountCredentialsByClientIDOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
			ClientID:        opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	amHashSet := utils.MapSliceToHashSet(accountCredentialsDTO.AuthMethods)
	if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
		return s.getAccountCredentialsKeyByID(ctx, getAccountCredentialsKeyByIDOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			publicKID:            opts.SecretID,
		})
	}
	if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
		return s.getAccountCredentialsSecretByID(ctx, getAccountCredentialsSecretByIDOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			secretID:             opts.SecretID,
		})
	}

	logger.WarnContext(ctx, "No auth method to get secret or key")
	return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to get secrets")
}

type revokeAccountCredentialsSecretOptions struct {
	requestID            string
	accountCredentialsID int32
	secretID             string
}

func (s *Services) revokeAccountCredentialsSecret(
	ctx context.Context,
	opts revokeAccountCredentialsSecretOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "revokeAccountCredentialsSecret").With(
		"accountCredentialsID", opts.accountCredentialsID,
		"secretID", opts.secretID,
	)
	logger.InfoContext(ctx, "Revoking account credentials secret...")

	secretDTO, serviceErr := s.getAccountCredentialsSecretByID(ctx, getAccountCredentialsSecretByIDOptions(opts))
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	secret, err := s.database.RevokeCredentialsSecret(ctx, secretDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to revoke account credentials secret", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapCredentialsSecretToDTO(&secret), nil
}

type revokeAccountCredentialsKeyOptions struct {
	requestID            string
	accountCredentialsID int32
	publicKID            string
}

func (s *Services) revokeAccountCredentialsKey(
	ctx context.Context,
	opts revokeAccountCredentialsKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "revokeAccountCredentialsKey").With(
		"accountCredentialsID", opts.accountCredentialsID,
		"publicKID", opts.publicKID,
	)

	secretDTO, serviceErr := s.getAccountCredentialsKeyByID(ctx, getAccountCredentialsKeyByIDOptions(opts))
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	secret, err := s.database.RevokeCredentialsKey(ctx, secretDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to revoke account credentials key", "error", err)
		return dtos.ClientCredentialsSecretDTO{}, exceptions.FromDBError(err)
	}

	return dtos.MapCredentialsKeyToDTO(&secret), nil
}

type RevokeAccountCredentialsSecretOrKeyOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	ClientID        string
	SecretID        string
}

func (s *Services) RevokeAccountCredentialsSecretOrKey(
	ctx context.Context,
	opts RevokeAccountCredentialsSecretOrKeyOptions,
) (dtos.ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "RevokeAccountCredentialsSecretOrKey").With(
		"clientId", opts.ClientID,
		"accountPublicID", opts.AccountPublicID,
		"secretID", opts.SecretID,
	)
	logger.InfoContext(ctx, "Revoking account credentials secret or key...")

	accountCredentialsDTO, serviceErr := s.getAccountCredentialsForMutation(
		ctx,
		getAccountCredentialsForMutationOptions{
			requestID:       opts.RequestID,
			accountPublicID: opts.AccountPublicID,
			accountVersion:  opts.AccountVersion,
			clientID:        opts.ClientID,
		},
	)
	if serviceErr != nil {
		return dtos.ClientCredentialsSecretDTO{}, serviceErr
	}

	amHashSet := utils.MapSliceToHashSet(accountCredentialsDTO.AuthMethods)
	if amHashSet.Contains(database.AuthMethodPrivateKeyJwt) {
		return s.revokeAccountCredentialsKey(ctx, revokeAccountCredentialsKeyOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			publicKID:            opts.SecretID,
		})
	}
	if amHashSet.Contains(database.AuthMethodClientSecretBasic) || amHashSet.Contains(database.AuthMethodClientSecretPost) {
		return s.revokeAccountCredentialsSecret(ctx, revokeAccountCredentialsSecretOptions{
			requestID:            opts.RequestID,
			accountCredentialsID: accountCredentialsDTO.ID(),
			secretID:             opts.SecretID,
		})
	}

	logger.WarnContext(ctx, "No auth method to revoke secret or key")
	return dtos.ClientCredentialsSecretDTO{}, exceptions.NewConflictError("No auth method to revoke secrets")
}

type listActiveAccountCredentialsKeysOptions struct {
	requestID       string
	accountPublicID uuid.UUID
}

func (s *Services) listActiveAccountCredentialsKeys(
	ctx context.Context,
	opts listActiveAccountCredentialsKeysOptions,
) (dtos.JWKsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountCredentialsLocation, "ListActiveAccountCredentialsKeys").With(
		"accountPublicID", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Listing account credentials keys...")

	keys, err := s.database.FindActiveAccountCredentialKeysByAccountPublicID(
		ctx,
		opts.accountPublicID,
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find active account credential keys", "error", err)
		return dtos.JWKsDTO{}, exceptions.FromDBError(err)
	}

	jwks, serviceErr := utils.MapSliceWithErr(keys, func(k *database.CredentialsKey) (utils.JWK, *exceptions.ServiceError) {
		jwk, err := utils.JsonToJWK(k.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decode public key", "error", err)
			return nil, exceptions.NewServerError()
		}

		return jwk, nil
	})
	if serviceErr != nil {
		return dtos.JWKsDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Found active account credential keys", "count", len(keys))
	return dtos.NewJWKsDTO(jwks), nil
}

type ListActiveAccountCredentialsKeysWithCacheOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
}

func (s *Services) ListActiveAccountCredentialsKeysWithCache(
	ctx context.Context,
	opts ListActiveAccountCredentialsKeysWithCacheOptions,
) (dtos.JWKsDTO, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsLocation, "ListActiveAccountCredentialsKeysWithCache").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Listing account credentials keys with cache...")

	cacheKey := fmt.Sprintf("%s:%s", accountCredentialsKeysCacheKeyPrefix, opts.AccountPublicID)
	jwksDTO, etag, err := cache.GetCachedResponse(s.cache, ctx, cache.GetCachedResponseOptions[dtos.JWKsDTO]{
		RequestID: opts.RequestID,
		Key:       cacheKey,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get cached account credentials keys", "error", err)
		return dtos.JWKsDTO{}, "", exceptions.NewServerError()
	}
	if etag != "" {
		logger.InfoContext(ctx, "Found cached account credentials keys", "etag", etag)
		return jwksDTO, etag, nil
	}

	jwksDTO, serviceErr := s.listActiveAccountCredentialsKeys(ctx, listActiveAccountCredentialsKeysOptions{
		requestID:       opts.RequestID,
		accountPublicID: opts.AccountPublicID,
	})
	if serviceErr != nil {
		return dtos.JWKsDTO{}, "", serviceErr
	}

	etag, err = cache.CacheResponse(s.cache, ctx, cache.CacheResponseOptions[dtos.JWKsDTO]{
		RequestID: opts.RequestID,
		Key:       cacheKey,
		TTL:       accountCredentialsKeysCacheTTL,
		Value:     jwksDTO,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to cache account credentials keys", "error", err)
		return dtos.JWKsDTO{}, "", exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Listed and cached account credentials keys", "etag", etag)
	return jwksDTO, etag, nil
}
