// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

const deksLocation = "deks"

func (s *Services) createGlobalDEK(
	ctx context.Context,
	requestID string,
	storeFN crypto.StoreDEK,
) *exceptions.ServiceError {
	logger := s.buildLogger(requestID, deksLocation, "createGlobalDEK")
	logger.InfoContext(ctx, "Creating and caching global DEK...")

	kekKID, serviceErr := s.GetOrCreateGlobalKEK(ctx, requestID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create global KEK", "error", serviceErr)
		return serviceErr
	}

	dekID, err := s.crypto.GenerateDEK(ctx, crypto.GenerateDEKOptions{
		RequestID: requestID,
		KEKid:     kekKID,
		StoreFN:   storeFN,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate global DEK", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Global DEK created and cached successfully", "dekKID", dekID)
	return nil
}

func (s *Services) buildGetEncGlobalDEK(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
) crypto.GetDEKtoEncrypt {
	return func() (crypto.DEKID, crypto.EncryptedDEK, uuid.UUID, *exceptions.ServiceError) {
		kid, dek, kekKID, ok, err := s.cache.GetEncDEK(ctx, cache.GetEncDEKOptions{
			RequestID: requestID,
			Suffix:    "global",
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewServerError()
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

			if serviceErr := s.createGlobalDEK(
				ctx,
				requestID,
				func(dekID string, encryptedDEK string, kekID uuid.UUID) (int32, *exceptions.ServiceError) {
					dekEnt, err := s.database.CreateDataEncryptionKey(ctx, database.CreateDataEncryptionKeyParams{
						Kid:       dekID,
						KekKid:    kekID,
						Usage:     database.DekUsageGlobal,
						ExpiresAt: time.Now().AddDate(0, 0, int(s.dekExpDays)),
					})
					if err != nil {
						logger.ErrorContext(ctx, "Failed to create DEK", "error", err)
						return 0, exceptions.NewServerError()
					}

					if err := s.cache.CacheEncDEK(ctx, cache.CacheEncDEKOptions{
						RequestID: requestID,
						DEK:       encryptedDEK,
						KID:       dekID,
						KEKid:     kekID,
						Suffix:    "global",
					}); err != nil {
						logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
						return 0, exceptions.NewServerError()
					}

					kid = dekID
					dek = dekEnt.Dek
					kekKID = dekEnt.KekKid
					return dekEnt.ID, nil
				}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "Created new DEK", "dekKID", kid)
			return kid, dek, kekKID, nil
		}

		if err := s.cache.CacheEncDEK(ctx, cache.CacheEncDEKOptions{
			RequestID: requestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			Suffix:    "global",
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewServerError()
		}

		return kid, dek, kekKID, nil
	}
}

func (s *Services) buildGetGlobalDecDEKFn(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
) crypto.GetDEKtoDecrypt {
	return func(kid string) (string, uuid.UUID, *exceptions.ServiceError) {
		dek, kekKID, ok, err := s.cache.GetDecDEK(ctx, cache.GetDecDEKOptions{
			RequestID: requestID,
			KID:       kid,
			Prefix:    "global",
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "error", err)
			return "", uuid.Nil, exceptions.NewServerError()
		}
		if ok {
			logger.InfoContext(ctx, "DEK found in cache", "dekKID", kid)
			return dek, kekKID, nil
		}

		dekEnt, err := s.database.FindDataEncryptionKeyByKID(ctx, kid)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK", "error", err)
			return "", uuid.Nil, exceptions.FromDBError(err)
		}

		if err := s.cache.CacheDecDEK(ctx, cache.CacheDecDEKOptions{
			RequestID: requestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			Prefix:    "global",
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			return "", uuid.Nil, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "DEK found in database", "dekKID", dekEnt.Kid)
		return dekEnt.Dek, dekEnt.KekKid, nil
	}
}

type createAndCacheAccountDEKOptions struct {
	requestID string
	accountID int32
	storeFN   crypto.StoreDEK
}

func (s *Services) createAndCacheAccountDEK(
	ctx context.Context,
	opts createAndCacheAccountDEKOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, deksLocation, "createAndCacheAccountDEK").With(
		"accountID", opts.accountID,
	)
	logger.InfoContext(ctx, "Creating and caching account DEK...")

	kekKID, serviceErr := s.GetOrCreateAccountKEK(ctx, GetOrCreateAccountKEKOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create account KEK", "serviceError", serviceErr)
		return serviceErr
	}

	dekID, err := s.crypto.GenerateDEK(ctx, crypto.GenerateDEKOptions{
		RequestID: opts.requestID,
		KEKid:     kekKID,
		StoreFN:   opts.storeFN,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate global DEK", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Global DEK created and cached successfully", "dekKID", dekID)
	return nil
}

type getEncAccountDEKOptions struct {
	requestID string
	accountID int32
}

func (s *Services) buildGetEncAccountDEK(
	ctx context.Context,
	logger *slog.Logger,
	opts getEncAccountDEKOptions,
) crypto.GetDEKtoEncrypt {
	return func() (crypto.DEKID, crypto.EncryptedDEK, uuid.UUID, *exceptions.ServiceError) {
		suffix := fmt.Sprintf("account:%d", opts.accountID)
		kid, dek, kekKID, ok, err := s.cache.GetEncDEK(ctx, cache.GetEncDEKOptions{
			RequestID: opts.requestID,
			Suffix:    suffix,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewServerError()
		}
		if ok {
			logger.InfoContext(ctx, "Global DEK found in cache", "dek_kid", kid)
			return kid, dek, kekKID, nil
		}

		dekEnt, err := s.database.FindAccountDataEncryptionKeyByAccountID(
			ctx,
			database.FindAccountDataEncryptionKeyByAccountIDParams{
				AccountID: opts.accountID,
				ExpiresAt: time.Now().Add(-2 * time.Hour),
			},
		)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get and cache global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			if serviceErr := s.createAndCacheAccountDEK(
				ctx,
				createAndCacheAccountDEKOptions{
					requestID: opts.requestID,
					accountID: opts.accountID,
					storeFN: func(dekID string, encryptedDEK string, kekID uuid.UUID) (int32, *exceptions.ServiceError) {
						qrs, txn, err := s.database.BeginTx(ctx)
						if err != nil {
							logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
							return 0, exceptions.FromDBError(err)
						}
						defer func() {
							logger.DebugContext(ctx, "Finalizing transaction")
							s.database.FinalizeTx(ctx, txn, err, serviceErr)
						}()

						dekEnt, err := qrs.CreateDataEncryptionKey(ctx, database.CreateDataEncryptionKeyParams{
							Kid:       dekID,
							KekKid:    kekID,
							Usage:     database.DekUsageAccount,
							ExpiresAt: time.Now().AddDate(0, 0, int(s.dekExpDays)),
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

						if err = s.cache.CacheEncDEK(ctx, cache.CacheEncDEKOptions{
							RequestID: opts.requestID,
							DEK:       encryptedDEK,
							KID:       dekID,
							KEKid:     kekID,
							Suffix:    suffix,
						}); err != nil {
							logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
							serviceErr = exceptions.NewServerError()
							return 0, serviceErr
						}

						kid = dekID
						dek = dekEnt.Dek
						kekKID = dekEnt.KekKid
						return dekEnt.ID, nil
					},
				},
			); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create global DEK", "serviceError", serviceErr)
				return "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "Created new DEK", "dekKID", kid)
			return kid, dek, kekKID, nil
		}

		if err := s.cache.CacheEncDEK(ctx, cache.CacheEncDEKOptions{
			RequestID: opts.requestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			Suffix:    suffix,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache global DEK", "error", err)
			return "", "", uuid.Nil, exceptions.NewServerError()
		}

		return kid, dek, kekKID, nil
	}
}

type buildGetDecAccountDEKFnOptions struct {
	requestID string
	accountID int32
}

func (s *Services) buildGetDecAccountDEKFn(
	ctx context.Context,
	logger *slog.Logger,
	opts buildGetDecAccountDEKFnOptions,
) crypto.GetDEKtoDecrypt {
	return func(kid string) (string, uuid.UUID, *exceptions.ServiceError) {
		prefix := fmt.Sprintf("account:%d", opts.accountID)
		dek, kekKID, ok, err := s.cache.GetDecDEK(ctx, cache.GetDecDEKOptions{
			RequestID: opts.requestID,
			KID:       kid,
			Prefix:    prefix,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "error", err)
			return "", uuid.Nil, exceptions.NewServerError()
		}
		if ok {
			logger.InfoContext(ctx, "DEK found in cache", "dekKID", kid)
			return dek, kekKID, nil
		}

		dekEnt, err := s.database.FindAccountDataEncryptionKeyByAccountIDAndKID(
			ctx,
			database.FindAccountDataEncryptionKeyByAccountIDAndKIDParams{
				AccountID: opts.accountID,
				Kid:       kid,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get DEK", "error", err)
			return "", uuid.Nil, exceptions.FromDBError(err)
		}

		if err := s.cache.CacheDecDEK(ctx, cache.CacheDecDEKOptions{
			RequestID: opts.requestID,
			DEK:       dekEnt.Dek,
			KID:       dekEnt.Kid,
			KEKid:     dekEnt.KekKid,
			Prefix:    prefix,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache DEK", "error", err)
			return "", uuid.Nil, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "DEK found in database", "dekKID", dekEnt.Kid)
		return dekEnt.Dek, dekEnt.KekKid, nil
	}
}
