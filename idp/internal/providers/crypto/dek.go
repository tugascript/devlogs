// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	dekLocation string = "dek"

	dekByteLen   int   = 32   // 256 bits
	dekCacheCost int64 = 1000 // Cost for caching DEK, used in Ristretto cache
)

func buildDEKCacheKey(dekID string) string {
	return fmt.Sprintf("dek:%s", dekID)
}

type StoreDEK = func(dekID, encryptedDEK string, kekID uuid.UUID) (int32, *exceptions.ServiceError)

type GenerateDEKOptions struct {
	RequestID string
	StoreFN   StoreDEK
	KEKid     uuid.UUID
}

func (e *Crypto) GenerateDEK(ctx context.Context, opts GenerateDEKOptions) (string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "GenerateDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating DEK...")

	dek, err := utils.GenerateRandomBytes(dekByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate DEK", "error", err)
		return "", err
	}

	dekID, encryptedDEK, err := e.encryptDEK(ctx, encryptDEKOptions{
		requestID: opts.RequestID,
		kekID:     opts.KEKid,
		dek:       dek,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt DEK", "error", err)
		return "", err
	}

	dbID, serviceErr := opts.StoreFN(dekID, encryptedDEK, opts.KEKid)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to store DEK", "serviceError", serviceErr)
		return "", serviceErr
	}

	if ok := e.localCache.SetWithTTL(buildDEKCacheKey(dekID), dek, dekCacheCost, e.dekTTL); !ok {
		logger.ErrorContext(ctx, "Failed to cache DEK", "dekID", dekID)
		return "", errors.New("failed to cache DEK")
	}

	logger.InfoContext(ctx, "DEK generated and stored successfully", "dekID", dekID, "dbID", dbID)
	return dekID, nil
}

type DEKID = string
type EncryptedDEK = string
type DEKCiphertext = string
type GetDEKtoDecrypt = func(dekID DEKID) (EncryptedDEK, uuid.UUID, *exceptions.ServiceError)
type GetDEKtoEncrypt = func() (DEKID, EncryptedDEK, uuid.UUID, *exceptions.ServiceError)

func (e *Crypto) getDecryptedDEK(
	ctx context.Context,
	requestID string,
	dekID string,
	encryptedDEK string,
	kekID uuid.UUID,
) ([]byte, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "getDecryptedDEK",
		RequestID: requestID,
	}).With("dekId", dekID, "kekId", kekID)
	logger.DebugContext(ctx, "Retrieving DEK from cache...")

	if dek, found := e.localCache.Get(buildDEKCacheKey(dekID)); found {
		logger.DebugContext(ctx, "DEK found in cache")
		return dek, nil
	}

	dek, err := e.decrypt(ctx, requestID, kekID, encryptedDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return nil, exceptions.NewServerError()
	}

	if ok := e.localCache.SetWithTTL(dekID, dek, dekCacheCost, e.dekTTL); !ok {
		logger.ErrorContext(ctx, "Failed to cache DEK")
		return nil, exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "DEK decrypted successfully")
	return dek, nil
}

func formatDEKCiphertext(dekID DEKID, ciphertext string) DEKCiphertext {
	return fmt.Sprintf("%s.%s", dekID, ciphertext)
}

type EncryptWithDEKOptions struct {
	RequestID string
	GetDEKfn  GetDEKtoEncrypt
	PlainText string
}

func (e *Crypto) EncryptWithDEK(
	ctx context.Context,
	opts EncryptWithDEKOptions,
) (DEKID, DEKCiphertext, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "EncryptWithDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Encrypting with DEK...")

	dekID, encDek, kekKID, serviceErr := opts.GetDEKfn()
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get DEK", "serviceError", serviceErr)
		return "", "", serviceErr
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, opts.RequestID, dekID, encDek, kekKID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return "", "", serviceErr
	}

	ciphertext, err := utils.Encrypt(opts.PlainText, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt with DEK", "error", err)
		return "", "", exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "Encrypted with DEK successfully", "dekID", dekID)
	return dekID, formatDEKCiphertext(dekID, ciphertext), nil
}

func splitDEKCiphertext(ciphertext DEKCiphertext) (DEKID, string, error) {
	parts := strings.Split(ciphertext, ".")
	if len(parts) != 2 {
		return "", "", errors.New("invalid DEK ciphertext format")
	}

	return parts[0], parts[1], nil
}

type DecryptWithDEKOptions struct {
	RequestID  string
	GetDEKfn   GetDEKtoDecrypt
	Ciphertext string
}

func (e *Crypto) DecryptWithDEK(ctx context.Context, opts DecryptWithDEKOptions) (string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "DecryptWithDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Encrypting with DEK...")

	dekID, ciphertext, err := splitDEKCiphertext(opts.Ciphertext)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to split DEK ciphertext", "error", err)
		return "", exceptions.NewServerError()
	}

	encDek, kekKID, serviceErr := opts.GetDEKfn(dekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get DEK", "serviceError", serviceErr)
		return "", serviceErr
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, opts.RequestID, dekID, encDek, kekKID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return "", serviceErr
	}

	secret, err := utils.Decrypt(ciphertext, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt secret", "error", err)
		return "", exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "Secret decrypted successfully")
	return secret, nil
}
