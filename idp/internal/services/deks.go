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
	"github.com/jackc/pgx/v5"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

const deksLocation = "deks"

type createDEKOptions struct {
	requestID string
	kekKID    uuid.UUID
	storeFN   crypto.StoreDEK
}

func (s *Services) createDEK(
	ctx context.Context,
	opts createDEKOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, deksLocation, "createDEK")
	logger.InfoContext(ctx, "Creating DEK...")

	dekID, err := s.crypto.GenerateDEK(ctx, crypto.GenerateDEKOptions{
		RequestID: opts.requestID,
		KEKid:     opts.kekKID,
		StoreFN:   opts.storeFN,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate DEK", "error", err)
		return exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "DEK created successfully", "dekKID", dekID)
	return nil
}

func (s *Services) buildStoreGlobalDEKfn(
	ctx context.Context,
	requestID string,
	data map[string]string,
) crypto.StoreDEK {
	logger := s.buildLogger(requestID, deksLocation, "storeGlobalDEK")
	logger.InfoContext(ctx, "Building store function for global DEK...")
	return func(dekID string, encryptedDEK string, kekID uuid.UUID) (int32, *exceptions.ServiceError) {
		dekEnt, err := s.database.CreateDataEncryptionKey(ctx, database.CreateDataEncryptionKeyParams{
			Kid:       dekID,
			KekKid:    kekID,
			Usage:     database.DekUsageGlobal,
			Dek:       encryptedDEK,
			ExpiresAt: time.Now().Add(s.dekExpDays),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create DEK", "error", err)
			return 0, exceptions.NewInternalServerError()
		}

		if err := s.cache.SaveEncDEK(ctx, cache.SaveEncDEKOptions{
			RequestID: requestID,
			DEK:       encryptedDEK,
			KID:       dekID,
			KEKid:     kekID,
			Suffix:    "global",
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			return 0, exceptions.NewInternalServerError()
		}

		data["dekID"] = dekID
		data["encryptedDEK"] = encryptedDEK
		logger.InfoContext(ctx, "Global DEK created and cached successfully", "dekID", dekID)
		return dekEnt.ID, nil
	}
}

func (s *Services) BuildGetEncGlobalDEKFn(
	ctx context.Context,
	requestID string,
) crypto.GetDEKtoEncrypt {
	logger := s.buildLogger(requestID, deksLocation, "BuildGetEncGlobalDEKFn")
	logger.InfoContext(ctx, "Build GetDEKtoEncrypt function...")
	return func() (crypto.DEKID, crypto.EncryptedDEK, uuid.UUID, *exceptions.ServiceError) {
		kid, dek, kekKID, ok, err := s.cache.GetEncDEK(ctx, cache.GetEncDEKOptions{
			RequestID: requestID,
			Suffix:    "global",
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewInternalServerError()
		}
		if ok {
			logger.InfoContext(ctx, "Global DEK found in cache", "dek_kid", kid)
			return kid, dek, kekKID, nil
		}

		dekEnt, err := s.database.FindValidGlobalDataEncryptionKey(ctx, time.Now().Add(-2*time.Hour))
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get and cache global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			kekKID, serviceErr := s.GetOrCreateGlobalKEK(ctx, requestID)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to get or create global KEK", "error", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			data := make(map[string]string)
			if serviceErr := s.createDEK(ctx, createDEKOptions{
				requestID: requestID,
				kekKID:    kekKID,
				storeFN:   s.buildStoreGlobalDEKfn(ctx, requestID, data),
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			kid, ok := data["dekID"]
			if !ok {
				logger.ErrorContext(ctx, "Global DEK not found in data map", "dekKID", kid)
				return "", "", uuid.Nil, exceptions.NewInternalServerError()
			}

			dek, ok := data["encryptedDEK"]
			if !ok {
				logger.ErrorContext(ctx, "Global DEK not found in data map", "dekKID", kid)
				return "", "", uuid.Nil, exceptions.NewInternalServerError()
			}

			logger.InfoContext(ctx, "Created new DEK", "dekKID", kid)
			return kid, dek, kekKID, nil
		}

		return dekEnt.Kid, dekEnt.Dek, dekEnt.KekKid, nil
	}
}

func (s *Services) BuildGetGlobalDecDEKFn(
	ctx context.Context,
	requestID string,
) crypto.GetDEKtoDecrypt {
	logger := s.buildLogger(requestID, deksLocation, "BuildGetGlobalDecDEKFn")
	logger.InfoContext(ctx, "Building GetDEKtoDecrypt function for global DEK...")

	return func(kid string) (crypto.EncryptedDEK, crypto.KEKID, crypto.IsExpiredDEK, *exceptions.ServiceError) {
		dek, kekKID, expiresAt, ok, err := s.cache.GetDecDEK(ctx, cache.GetDecDEKOptions{
			RequestID: requestID,
			KID:       kid,
			Prefix:    "global",
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "error", err)
			return "", uuid.Nil, false, exceptions.NewInternalServerError()
		}

		now := time.Now()
		if ok {
			logger.InfoContext(ctx, "DEK found in cache", "dekKID", kid)
			return dek, kekKID, now.After(expiresAt), nil
		}

		dekEnt, err := s.database.FindDataEncryptionKeyByKID(ctx, kid)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK", "error", err)
			return "", uuid.Nil, false, exceptions.FromDBError(err)
		}

		if err := s.cache.SaveDecDEK(ctx, cache.SaveDecDEKOptions{
			RequestID: requestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			ExpiresAt: dekEnt.ExpiresAt,
			Prefix:    "global",
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			return "", uuid.Nil, false, exceptions.NewInternalServerError()
		}

		logger.InfoContext(ctx, "DEK found in database", "dekKID", dekEnt.Kid)
		return dekEnt.Dek, dekEnt.KekKid, now.After(dekEnt.ExpiresAt), nil
	}
}

type buildStoreAccountDEKOptions struct {
	requestID string
	accountID int32
	data      map[string]string
	queries   *database.Queries
}

func (s *Services) buildStoreAccountDEKfn(
	ctx context.Context,
	opts buildStoreAccountDEKOptions,
) crypto.StoreDEK {
	logger := s.buildLogger(opts.requestID, deksLocation, "buildStoreAccountDEKfn")
	logger.InfoContext(ctx, "Building store function for account DEK...")

	return func(dekID string, encryptedDEK string, kekID uuid.UUID) (int32, *exceptions.ServiceError) {
		var qrs *database.Queries
		var txn pgx.Tx
		var err error
		var serviceErr *exceptions.ServiceError
		if opts.queries != nil {
			qrs = opts.queries
		} else {
			qrs, txn, err = s.database.BeginTx(ctx)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
				return 0, exceptions.FromDBError(err)
			}
			defer func() {
				logger.DebugContext(ctx, "Finalizing transaction")
				s.database.FinalizeTx(ctx, txn, err, serviceErr)
			}()
		}

		dekEnt, err := qrs.CreateDataEncryptionKey(ctx, database.CreateDataEncryptionKeyParams{
			Kid:       dekID,
			Dek:       encryptedDEK,
			KekKid:    kekID,
			Usage:     database.DekUsageAccount,
			ExpiresAt: time.Now().Add(s.dekExpDays),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create DEK", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return 0, serviceErr
		}

		if err = qrs.CreateAccountDataEncryptionKey(ctx, database.CreateAccountDataEncryptionKeyParams{
			AccountID:           opts.accountID,
			DataEncryptionKeyID: dekEnt.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account DEK", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return 0, serviceErr
		}

		if err = s.cache.SaveEncDEK(ctx, cache.SaveEncDEKOptions{
			RequestID: opts.requestID,
			DEK:       encryptedDEK,
			KID:       dekID,
			KEKid:     kekID,
			Suffix:    fmt.Sprintf("account:%d", opts.accountID),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			serviceErr = exceptions.NewInternalServerError()
			return 0, serviceErr
		}

		logger.InfoContext(ctx, "Account DEK created and cached successfully", "dekID", dekID, "AccountID", opts.accountID)
		opts.data["dekID"] = dekID
		opts.data["encryptedDEK"] = encryptedDEK
		return dekEnt.ID, nil
	}
}

type BuildGetEncAccountDEKOptions struct {
	RequestID string
	AccountID int32
	Queries   *database.Queries
}

func (s *Services) BuildGetEncAccountDEKfn(
	ctx context.Context,
	opts BuildGetEncAccountDEKOptions,
) crypto.GetDEKtoEncrypt {
	logger := s.buildLogger(opts.RequestID, deksLocation, "BuildGetEncAccountDEKfn").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Building GetDEKtoEncrypt function for account DEK...")

	return func() (crypto.DEKID, crypto.EncryptedDEK, uuid.UUID, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting account DEK from cache")
		suffix := fmt.Sprintf("account:%d", opts.AccountID)
		kid, dek, kekKID, found, err := s.cache.GetEncDEK(ctx, cache.GetEncDEKOptions{
			RequestID: opts.RequestID,
			Suffix:    suffix,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get account DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewInternalServerError()
		}
		if found {
			logger.InfoContext(ctx, "Account DEK found in cache", "dek_kid", kid)
			return kid, dek, kekKID, nil
		}

		logger.InfoContext(ctx, "DEK not found in cache, checking database...")
		qrs := s.mapQueries(opts.Queries)
		dekEnt, err := qrs.FindAccountDataEncryptionKeyByAccountID(
			ctx,
			database.FindAccountDataEncryptionKeyByAccountIDParams{
				AccountID: opts.AccountID,
				ExpiresAt: time.Now().Add(-2 * time.Hour),
			},
		)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get and cache global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "DEK not found in database, creating new one...")
			kekKID, serviceErr := s.GetOrCreateAccountKEK(ctx, GetOrCreateAccountKEKOptions(opts))
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to get or create account KEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			data := make(map[string]string)
			if serviceErr := s.createDEK(
				ctx,
				createDEKOptions{
					requestID: opts.RequestID,
					kekKID:    kekKID,
					storeFN: s.buildStoreAccountDEKfn(ctx, buildStoreAccountDEKOptions{
						requestID: opts.RequestID,
						accountID: opts.AccountID,
						data:      data,
					}),
				},
			); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			kid, ok := data["dekID"]
			if !ok {
				logger.ErrorContext(ctx, "Global DEK not found in data map", "dekKID", kid)
				return "", "", uuid.Nil, exceptions.NewInternalServerError()
			}

			dek, ok := data["encryptedDEK"]
			if !ok {
				logger.ErrorContext(ctx, "Global DEK not found in data map", "dekKID", kid)
				return "", "", uuid.Nil, exceptions.NewInternalServerError()
			}

			logger.InfoContext(ctx, "Created and cached new DEK", "dekKID", kid)
			return kid, dek, kekKID, nil
		}

		if err := s.cache.SaveEncDEK(ctx, cache.SaveEncDEKOptions{
			RequestID: opts.RequestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			Suffix:    suffix,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewInternalServerError()
		}

		return dekEnt.Kid, dekEnt.Dek, dekEnt.KekKid, nil
	}
}

type BuildGetDecAccountDEKFnOptions struct {
	RequestID string
	AccountID int32
	Queries   *database.Queries
}

func (s *Services) BuildGetDecAccountDEKFn(
	ctx context.Context,
	opts BuildGetDecAccountDEKFnOptions,
) crypto.GetDEKtoDecrypt {
	logger := s.buildLogger(opts.RequestID, deksLocation, "BuildGetDecAccountDEKFn").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Building GetDEKtoDecrypt function for account DEK...")

	return func(kid string) (crypto.EncryptedDEK, crypto.KEKID, crypto.IsExpiredDEK, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting account DEK from cache")
		prefix := fmt.Sprintf("account:%d", opts.AccountID)
		dek, kekKID, expiresAt, found, err := s.cache.GetDecDEK(ctx, cache.GetDecDEKOptions{
			RequestID: opts.RequestID,
			KID:       kid,
			Prefix:    prefix,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "error", err)
			return "", uuid.Nil, false, exceptions.NewInternalServerError()
		}

		now := time.Now()
		if found {
			logger.InfoContext(ctx, "DEK found in cache", "dekKID", kid)
			return dek, kekKID, now.After(expiresAt), nil
		}

		logger.InfoContext(ctx, "DEK not found in cache, checking database...")
		dekEnt, err := s.mapQueries(opts.Queries).FindAccountDataEncryptionKeyByAccountIDAndKID(
			ctx,
			database.FindAccountDataEncryptionKeyByAccountIDAndKIDParams{
				AccountID: opts.AccountID,
				Kid:       kid,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK", "error", err)
			return "", uuid.Nil, false, exceptions.FromDBError(err)
		}

		if err := s.cache.SaveDecDEK(ctx, cache.SaveDecDEKOptions{
			RequestID: opts.RequestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			ExpiresAt: dekEnt.ExpiresAt,
			Prefix:    prefix,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			return "", uuid.Nil, false, exceptions.NewInternalServerError()
		}

		logger.InfoContext(ctx, "DEK found in database", "dekKID", dekEnt.Kid)
		return dekEnt.Dek, dekEnt.KekKid, now.After(dekEnt.ExpiresAt), nil
	}
}
