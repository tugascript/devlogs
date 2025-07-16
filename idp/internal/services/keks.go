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
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

const keksLocation = "keks"

func (s *Services) createAndCacheGlobalKEK(
	ctx context.Context,
	requestID string,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, keksLocation, "createAndCacheGlobalKEK")
	logger.InfoContext(ctx, "Creating global KEK...")

	_, keyID, err := s.crypto.GenerateKEK(ctx, crypto.GenerateKEKOptions{
		RequestID: requestID,
		StoreFN: func(keyID uuid.UUID) (int32, error) {
			return s.database.CreateKeyEncryptionKey(ctx, database.CreateKeyEncryptionKeyParams{
				Kid:            keyID,
				Usage:          database.KekUsageGlobal,
				NextRotationAt: time.Now().AddDate(0, 0, int(s.kekExpDays)),
			})
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate global KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
		RequestID: requestID,
		KID:       keyID,
		Prefix:    string(database.KekUsageGlobal),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache global KEK", "error", err)
	}

	return keyID, nil
}

func (s *Services) getAndCacheGlobalKEK(
	ctx context.Context,
	requestID string,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, keksLocation, "getAndCacheGlobalKEK")
	logger.InfoContext(ctx, "Getting and caching global KEK...")

	kek, ok, err := s.cache.GetKEKUUID(ctx, cache.GetKEKUUIDOptions{
		RequestID: requestID,
		Prefix:    string(database.KekUsageGlobal),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get global KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}
	if ok {
		return kek, nil
	}

	kekEntity, err := s.database.FindGlobalKeyEncryptionKey(ctx)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find global KEK", "error", err)
			return uuid.Nil, serviceErr
		}

		logger.WarnContext(ctx, "Global KEK not found")
		return uuid.Nil, serviceErr
	}

	if kekEntity.NextRotationAt.After(time.Now()) {
		if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
			RequestID: requestID,
			KID:       kekEntity.Kid,
			Prefix:    string(database.KekUsageGlobal),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache global KEK", "error", err)
			return uuid.Nil, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Global KEK found in database", "kid", kekEntity.Kid)
		return kekEntity.Kid, nil
	}

	logger.InfoContext(ctx, "Global KEK is expired, rotating current one...")
	if _, _, err := s.crypto.RotateKEK(ctx, crypto.RotateKEKOptions{
		RequestID: requestID,
		KEKid:     kekEntity.Kid,
		StoreFN: func(_ uuid.UUID) (int32, error) {
			return s.database.RotateKeyEncryptionKey(ctx, database.RotateKeyEncryptionKeyParams{
				ID:             kekEntity.ID,
				NextRotationAt: time.Now().AddDate(0, 0, int(s.kekExpDays)),
			})
		},
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to rotate global KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
		RequestID: requestID,
		KID:       kekEntity.Kid,
		Prefix:    string(database.KekUsageGlobal),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache global KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Global KEK rotated successfully")
	return kekEntity.Kid, nil
}

func (s *Services) GetOrCreateGlobalKEK(
	ctx context.Context,
	requestID string,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, keksLocation, "GetOrCreateGlobalKEK")
	logger.InfoContext(ctx, "Getting or creating global KEK...")

	kek, serviceErr := s.getAndCacheGlobalKEK(ctx, requestID)
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Global KEK not found, creating new one...")
			return s.createAndCacheGlobalKEK(ctx, requestID)
		}

		logger.ErrorContext(ctx, "Failed to get global KEK", "serviceError", serviceErr)
		return uuid.Nil, serviceErr
	}

	logger.InfoContext(ctx, "Global KEK found", "kid", kek)
	return kek, nil
}

type createAndCacheAccountKEKOptions struct {
	requestID string
	accountID int32
}

func (s *Services) createAndCacheAccountKEK(
	ctx context.Context,
	opts createAndCacheAccountKEKOptions,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, keksLocation, "createAndCacheAccountKEK")
	logger.InfoContext(ctx, "Creating and caching account KEK...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return uuid.Nil, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	dbID, keyID, err := s.crypto.GenerateKEK(ctx, crypto.GenerateKEKOptions{
		RequestID: opts.requestID,
		StoreFN: func(keyID uuid.UUID) (int32, error) {
			return qrs.CreateKeyEncryptionKey(ctx, database.CreateKeyEncryptionKeyParams{
				Kid:            keyID,
				Usage:          database.KekUsageAccount,
				NextRotationAt: time.Now().AddDate(0, 0, int(s.kekExpDays)),
			})
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate account KEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return uuid.Nil, serviceErr
	}

	if err := qrs.CreateAccountKeyEncryptionKey(ctx, database.CreateAccountKeyEncryptionKeyParams{
		AccountID:          opts.accountID,
		KeyEncryptionKeyID: dbID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create account KEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return uuid.Nil, serviceErr
	}

	if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
		RequestID: opts.requestID,
		KID:       keyID,
		Prefix:    fmt.Sprintf("%s:%d", database.KekUsageAccount, opts.accountID),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache account KEK", "error", err)
		serviceErr = exceptions.NewServerError()
		return uuid.Nil, serviceErr
	}

	return keyID, nil
}

type getAndCacheAccountKEKOptions struct {
	requestID string
	accountID int32
}

func (s *Services) getAndCacheAccountKEK(
	ctx context.Context,
	opts getAndCacheAccountKEKOptions,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, keksLocation, "getAndCacheAccountKEK").With("AccountID", opts.accountID)
	logger.InfoContext(ctx, "Getting and caching account KEK...")

	prefix := fmt.Sprintf("%s:%d", database.KekUsageAccount, opts.accountID)
	kek, ok, err := s.cache.GetKEKUUID(ctx, cache.GetKEKUUIDOptions{
		RequestID: opts.requestID,
		Prefix:    prefix,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}
	if ok {
		logger.InfoContext(ctx, "Account KEK found in cache", "kid", kek)
		return kek, nil
	}

	kekEntity, err := s.database.FindAccountKeyEncryptionKeyByAccountID(ctx, opts.accountID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account KEK", "error", err)
			return uuid.Nil, serviceErr
		}

		logger.WarnContext(ctx, "Account KEK not found")
		return uuid.Nil, serviceErr
	}

	if kekEntity.NextRotationAt.After(time.Now()) {
		if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
			RequestID: opts.requestID,
			KID:       kekEntity.Kid,
			Prefix:    prefix,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache account KEK", "error", err)
			return uuid.Nil, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Account KEK found in database", "kid", kekEntity.Kid)
		return kekEntity.Kid, nil
	}

	logger.InfoContext(ctx, "Account KEK is expired, rotating current one...")
	if _, _, err := s.crypto.RotateKEK(ctx, crypto.RotateKEKOptions{
		RequestID: opts.requestID,
		KEKid:     kekEntity.Kid,
		StoreFN: func(_ uuid.UUID) (int32, error) {
			return s.database.RotateKeyEncryptionKey(ctx, database.RotateKeyEncryptionKeyParams{
				ID:             kekEntity.ID,
				NextRotationAt: time.Now().AddDate(0, 0, int(s.kekExpDays)),
			})
		},
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to rotate account KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	if err := s.cache.SaveKEKUUID(ctx, cache.SaveKEKUUIDOptions{
		RequestID: opts.requestID,
		KID:       kekEntity.Kid,
		Prefix:    prefix,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache account KEK", "error", err)
		return uuid.Nil, exceptions.NewServerError()
	}

	return kekEntity.Kid, nil
}

type GetOrCreateAccountKEKOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetOrCreateAccountKEK(
	ctx context.Context,
	opts GetOrCreateAccountKEKOptions,
) (uuid.UUID, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, keksLocation, "GetOrCreateAccountKEK")
	logger.InfoContext(ctx, "Getting or creating account KEK...")

	kek, serviceErr := s.getAndCacheAccountKEK(ctx, getAndCacheAccountKEKOptions{
		requestID: opts.RequestID,
		accountID: opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account KEK not found, creating new one...")
			return s.createAndCacheAccountKEK(ctx, createAndCacheAccountKEKOptions{
				requestID: opts.RequestID,
				accountID: opts.AccountID,
			})
		}

		logger.ErrorContext(ctx, "Failed to get account KEK", "serviceError", serviceErr)
		return uuid.Nil, serviceErr
	}

	logger.InfoContext(ctx, "Account KEK found", "kid", kek)
	return kek, nil
}
