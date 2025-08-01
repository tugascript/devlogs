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

	dekByteLen int = 32 // 256 bits
)

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

	logger.InfoContext(ctx, "DEK generated and stored successfully", "dekID", dekID, "dbID", dbID)
	return dekID, nil
}

type DEKID = string
type EncryptedDEK = string
type DEKCiphertext = string
type IsExpiredDEK = bool
type EntityID = string
type GetDEKtoDecrypt = func(dekID DEKID) (EncryptedDEK, KEKID, IsExpiredDEK, *exceptions.ServiceError)
type GetDEKtoEncrypt = func() (DEKID, EncryptedDEK, uuid.UUID, *exceptions.ServiceError)
type StoreReEncryptedData = func(entityID EntityID, dekID DEKID, ciphertext DEKCiphertext) *exceptions.ServiceError

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

	dek, err := e.decrypt(ctx, opts.RequestID, kekKID, encDek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return "", "", exceptions.NewInternalServerError()
	}
	defer utils.WipeBytes(dek)

	ciphertext, err := utils.Encrypt(opts.PlainText, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt with DEK", "error", err)
		return "", "", exceptions.NewInternalServerError()
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
	RequestID              string
	GetDecryptDEKfn        GetDEKtoDecrypt
	GetEncryptDEKfn        GetDEKtoEncrypt
	StoreReEncryptedDataFn StoreReEncryptedData
	EntityID               EntityID
	Ciphertext             string
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
		return "", exceptions.NewInternalServerError()
	}

	encDek, kekKID, isExpired, serviceErr := opts.GetDecryptDEKfn(dekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get DEK", "serviceError", serviceErr)
		return "", serviceErr
	}

	dek, err := e.decrypt(ctx, opts.RequestID, kekKID, encDek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	defer utils.WipeBytes(dek)

	secret, err := utils.Decrypt(ciphertext, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt secret", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	if isExpired {
		logger.DebugContext(ctx, "Secret is expired, re-encrypting...")
		newDEKid, newCiphertext, serviceErr := e.EncryptWithDEK(ctx, EncryptWithDEKOptions{
			RequestID: opts.RequestID,
			GetDEKfn:  opts.GetEncryptDEKfn,
			PlainText: secret,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to re-encrypt secret", "serviceError", serviceErr)
			return "", serviceErr
		}
		if serviceErr := opts.StoreReEncryptedDataFn(opts.EntityID, newDEKid, newCiphertext); serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to store re-encrypted data", "serviceError", serviceErr)
			return "", serviceErr
		}
	}

	logger.DebugContext(ctx, "Secret decrypted successfully")
	return secret, nil
}
