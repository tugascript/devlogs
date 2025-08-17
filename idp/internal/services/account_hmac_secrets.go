// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"time"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

const accountHMACSecretsLocation = "account_hmac_secrets"

type buildStoreAccountHMACSecretOptions struct {
	requestID string
	accountID int32
	data      map[string]string
	queries   *database.Queries
}

func (s *Services) buildStoreAccountHMACSecretFn(
	ctx context.Context,
	opts buildStoreAccountHMACSecretOptions,
) crypto.StoreHMACSecret {
	logger := s.buildLogger(opts.requestID, accountHMACSecretsLocation, "buildStoreAccountHMACSecretFn")
	logger.InfoContext(ctx, "Building store function for account HMAC secret...")

	return func(dekID string, secretID string, encryptedSecret string) (int32, *exceptions.ServiceError) {
		id, err := s.mapQueries(opts.queries).CreateAccountHMACSecret(ctx, database.CreateAccountHMACSecretParams{
			AccountID: opts.accountID,
			SecretID:  secretID,
			Secret:    encryptedSecret,
			DekKid:    dekID,
			ExpiresAt: time.Now().Add(s.hmacSecretExpDays),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create account HMAC secret", "error", err)
			return 0, exceptions.FromDBError(err)
		}

		opts.data["secretID"] = secretID
		opts.data["encryptedSecret"] = encryptedSecret
		logger.InfoContext(ctx, "Created account HMAC secret", "id", id)
		return id, nil
	}
}

type BuildGetHMACSecretFNOptions struct {
	RequestID string
	AccountID int32
	Queries   *database.Queries
}

func (s *Services) BuildGetHMACSecretFN(
	ctx context.Context,
	opts BuildGetHMACSecretFNOptions,
) crypto.GetHMACSecretFN {
	logger := s.buildLogger(opts.RequestID, accountHMACSecretsLocation, "BuildGetHMACSecretFN")
	logger.InfoContext(ctx, "Building get HMAC secret function...")

	return func() (string, crypto.DEKCiphertext, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting HMAC secret...")

		secret, err := s.mapQueries(opts.Queries).FindValidHMACSecretByAccountID(ctx, opts.AccountID)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to find account HMAC secret", "error", err)
				return "", "", serviceErr
			}

			data := make(map[string]string)
			if _, serviceErr := s.crypto.GenerateHMACSecret(ctx, crypto.GenerateHMACSecretOptions{
				RequestID: opts.RequestID,
				StoreFN: s.buildStoreAccountHMACSecretFn(ctx, buildStoreAccountHMACSecretOptions{
					requestID: opts.RequestID,
					accountID: opts.AccountID,
					queries:   opts.Queries,
					data:      data,
				}),
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to generate account HMAC secret", "serviceError", serviceErr)
				return "", "", serviceErr
			}

			return data["secretID"], data["encryptedSecret"], nil
		}

		return secret.SecretID, secret.Secret, nil
	}
}

type BuildUpdateHMACSecretFNOptions struct {
	RequestID string
	AccountID int32
	Queries   *database.Queries
}

func (s *Services) BuildUpdateHMACSecretFN(
	ctx context.Context,
	opts BuildUpdateHMACSecretFNOptions,
) crypto.StoreReEncryptedData {
	logger := s.buildLogger(opts.RequestID, accountHMACSecretsLocation, "BuildUpdateHMACSecretFN")
	logger.InfoContext(ctx, "Building update HMAC secret function...")

	return func(secretID crypto.EntityID, dekID crypto.DEKID, encPrivKey crypto.DEKCiphertext) *exceptions.ServiceError {
		logger.InfoContext(ctx, "Updating HMAC secret...")

		qrs := s.mapQueries(opts.Queries)
		secret, err := qrs.FindAccountHMACSecretByAccountIDAndSecretID(ctx, database.FindAccountHMACSecretByAccountIDAndSecretIDParams{
			AccountID: opts.AccountID,
			SecretID:  secretID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find account HMAC secret", "error", err)
			return exceptions.FromDBError(err)
		}

		if err := qrs.UpdateAccountHMACSecret(ctx, database.UpdateAccountHMACSecretParams{
			ID:     secret.ID,
			Secret: encPrivKey,
			DekKid: dekID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account HMAC secret", "error", err)
			return exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Updated HMAC secret successfully")
		return nil
	}
}

type BuildGetHMACSecretByIDFNOptions struct {
	RequestID string
	AccountID int32
	Queries   *database.Queries
}

func (s *Services) BuildGetHMACSecretByIDFN(
	ctx context.Context,
	opts BuildGetHMACSecretByIDFNOptions,
) crypto.GetHMACSecretByIDfn {
	logger := s.buildLogger(opts.RequestID, accountHMACSecretsLocation, "BuildGetHMACSecretByIDFN")
	logger.InfoContext(ctx, "Building get HMAC secret by ID function...")

	return func(secretID crypto.SecretID) (crypto.DEKCiphertext, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting HMAC secret by ID...", "secretID", secretID)

		secret, err := s.mapQueries(opts.Queries).FindAccountHMACSecretByAccountIDAndSecretID(
			ctx,
			database.FindAccountHMACSecretByAccountIDAndSecretIDParams{
				AccountID: opts.AccountID,
				SecretID:  secretID,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find account HMAC secret", "error", err)
			return "", exceptions.FromDBError(err)
		}

		return secret.Secret, nil
	}
}
