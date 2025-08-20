// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	hmacLocation string = "hmac"

	hmacSecretByteLength int = 32
)

func encodeHMACSecret(secret []byte) string {
	return base64.StdEncoding.EncodeToString(secret)
}

func decodeHMACSecret(secret string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(secret)
}

type SecretID = string

type StoreHMACSecret = func(dekID string, secretID SecretID, encryptedSecret string) (int32, *exceptions.ServiceError)

type GenerateHMACSecretOptions struct {
	RequestID string
	StoreFN   StoreHMACSecret
	GetDEKfn  GetDEKtoEncrypt
}

func (e *Crypto) GenerateHMACSecret(ctx context.Context, opts GenerateHMACSecretOptions) (string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  hmacLocation,
		Method:    "GenerateHMACSecret",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating HMAC secret...")

	secretBytes, err := utils.GenerateRandomBytes(hmacSecretByteLength)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate HMAC secret", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	secretID := utils.ExtractSecretID(secretBytes)

	dekID, encryptedSecret, serviceErr := e.EncryptWithDEK(ctx, EncryptWithDEKOptions{
		RequestID: opts.RequestID,
		GetDEKfn:  opts.GetDEKfn,
		PlainText: encodeHMACSecret(secretBytes),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to encrypt HMAC secret", "serviceError", serviceErr)
		return "", exceptions.NewInternalServerError()
	}

	dbID, serviceErr := opts.StoreFN(dekID, secretID, encryptedSecret)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to store HMAC secret", "serviceError", serviceErr)
		return "", exceptions.NewInternalServerError()
	}

	logger.InfoContext(ctx, "HMAC secret generated and stored successfully", "dekID", dekID, "dbID", dbID)
	return secretID, nil
}

func encodeHMACData(data []byte) string {
	return hex.EncodeToString(data)
}

func decodeHMACData(data string) ([]byte, error) {
	return hex.DecodeString(data)
}

type GetHMACSecretFN = func() (string, DEKCiphertext, *exceptions.ServiceError)

type StoreHashedData = func(secretID string, hashedData string) *exceptions.ServiceError

type HMACSha256HashOptions struct {
	RequestID                    string
	PlainText                    string
	GetHMACSecretFN              GetHMACSecretFN
	StoreHashedDataFN            StoreHashedData
	GetDecryptDEKfn              GetDEKtoDecrypt
	GetEncryptDEKfn              GetDEKtoEncrypt
	StoreReEncryptedHMACSecretFN StoreReEncryptedData
}

func (e *Crypto) HMACSha256Hash(ctx context.Context, opts HMACSha256HashOptions) *exceptions.ServiceError {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  hmacLocation,
		Method:    "HMACSha256Hash",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Calculating HMAC SHA256...")

	secretID, dekCiphertext, serviceErr := opts.GetHMACSecretFN()
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get HMAC secret", "serviceError", serviceErr)
		return serviceErr
	}

	encodedSecret, serviceErr := e.DecryptWithDEK(ctx, DecryptWithDEKOptions{
		RequestID:              opts.RequestID,
		GetDecryptDEKfn:        opts.GetDecryptDEKfn,
		GetEncryptDEKfn:        opts.GetEncryptDEKfn,
		StoreReEncryptedDataFn: opts.StoreReEncryptedHMACSecretFN,
		EntityID:               secretID,
		Ciphertext:             dekCiphertext,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt HMAC secret", "serviceError", serviceErr)
		return serviceErr
	}

	secret, err := decodeHMACSecret(encodedSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode HMAC secret", "error", err)
		return exceptions.NewInternalServerError()
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(opts.PlainText))
	if serviceErr := opts.StoreHashedDataFN(secretID, encodeHMACData(mac.Sum(nil))); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to store hashed data", "serviceError", serviceErr)
		return exceptions.NewInternalServerError()
	}

	return nil
}

type GetHMACSecretByIDfn = func(secretID SecretID) (DEKCiphertext, *exceptions.ServiceError)

type GetHashedSecretFN = func() (SecretID, string, *exceptions.ServiceError)

type HMACSha256CompareHashOptions struct {
	RequestID                    string
	PlainText                    string
	HashedSecretFN               GetHashedSecretFN
	GetHMACSecretByIDFN          GetHMACSecretByIDfn
	GetDecryptDEKfn              GetDEKtoDecrypt
	GetEncryptDEKfn              GetDEKtoEncrypt
	StoreReEncryptedHMACSecretFN StoreReEncryptedData
}

func (e *Crypto) HMACSha256CompareHash(ctx context.Context, opts HMACSha256CompareHashOptions) *exceptions.ServiceError {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  hmacLocation,
		Method:    "HMACSha256CompareHash",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Comparing HMAC SHA256...")

	secretID, hashedSecret, serviceErr := opts.HashedSecretFN()
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get hashed secret", "serviceError", serviceErr)
		return serviceErr
	}

	dekCiphertext, serviceErr := opts.GetHMACSecretByIDFN(secretID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get HMAC secret by ID", "serviceError", serviceErr)
		return serviceErr
	}

	encodedSecret, serviceErr := e.DecryptWithDEK(ctx, DecryptWithDEKOptions{
		RequestID:              opts.RequestID,
		GetDecryptDEKfn:        opts.GetDecryptDEKfn,
		GetEncryptDEKfn:        opts.GetEncryptDEKfn,
		StoreReEncryptedDataFn: opts.StoreReEncryptedHMACSecretFN,
		EntityID:               secretID,
		Ciphertext:             dekCiphertext,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt HMAC secret", "serviceError", serviceErr)
		return serviceErr
	}

	secret, err := decodeHMACSecret(encodedSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode HMAC secret", "error", err)
		return exceptions.NewInternalServerError()
	}

	hashedSecretBytes, err := decodeHMACData(hashedSecret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode hashed secret", "error", err)
		return exceptions.NewInternalServerError()
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(opts.PlainText))
	if !utils.CompareSha256(mac.Sum(nil), hashedSecretBytes) {
		logger.WarnContext(ctx, "HMAC SHA256 hash mismatch", "plainText", opts.PlainText, "hashedSecret", hashedSecret)
		return exceptions.NewUnauthorizedError()
	}

	return nil
}
