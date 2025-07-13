// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	kekLocation string = "kek"

	rotatePath string = "rotate"
)

var kekKeyConfig = map[string]any{
	"type": "aes256-gcm96",
}

func buildKEKPath(kekPath string, keyID uuid.UUID) string {
	return kekPath + "/" + keyID.String()
}

func (e *Crypto) createTransitKey(ctx context.Context) (uuid.UUID, error) {
	keyID := uuid.New()
	if _, err := e.opLogical.WriteWithContext(ctx, buildKEKPath(e.kekPath, keyID), kekKeyConfig); err != nil {
		return uuid.Nil, fmt.Errorf("failed to create transit key: %w", err)
	}

	return keyID, nil
}

func (e *Crypto) deleteTransitKey(ctx context.Context, keyID uuid.UUID) error {
	if _, err := e.opLogical.DeleteWithContext(ctx, buildKEKPath(e.kekPath, keyID)); err != nil {
		return fmt.Errorf("failed to delete transit key: %w", err)
	}

	return nil
}

func (e *Crypto) rotateKey(ctx context.Context, keyID uuid.UUID) error {
	if _, err := e.opLogical.WriteWithContext(ctx, buildKEKPath(e.kekPath, keyID)+rotatePath, nil); err != nil {
		return fmt.Errorf("failed to rotate KEK: %w", err)
	}

	return nil
}

type KEKID = uuid.UUID
type StoreKEK = func(keyID KEKID) (int32, error)

type GenerateKEKOptions struct {
	RequestID string
	StoreFN   StoreKEK
}

func (e *Crypto) GenerateKEK(ctx context.Context, opts GenerateKEKOptions) (int32, uuid.UUID, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "GenerateKEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating KEK...")

	keyID, err := e.createTransitKey(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create transit key", "error", err)
		return 0, uuid.Nil, err
	}

	dbID, err := opts.StoreFN(keyID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to store KEK", "error", err)

		if delErr := e.deleteTransitKey(ctx, keyID); delErr != nil {
			logger.ErrorContext(ctx, "Failed to delete transit key after storing KEK failed", "error", delErr)
		}

		return 0, uuid.Nil, err
	}

	logger.DebugContext(ctx, "KEK generated successfully", "keyId", keyID, "dbId", dbID)
	return dbID, keyID, nil
}

type RotateKEKOptions struct {
	RequestID string
	StoreFN   StoreKEK
	KEKid     KEKID
}

func (e *Crypto) RotateKEK(ctx context.Context, opts RotateKEKOptions) (int32, uuid.UUID, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "RotateKEK",
		RequestID: opts.RequestID,
	}).With("kekID", opts.KEKid.String())
	logger.DebugContext(ctx, "Rotating KEK...")

	if err := e.rotateKey(ctx, opts.KEKid); err != nil {
		logger.ErrorContext(ctx, "Failed to rotate KEK", "error", err)
		return 0, uuid.Nil, err
	}

	dbID, err := opts.StoreFN(opts.KEKid)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to store KEK", "error", err)
		return 0, uuid.Nil, err
	}

	logger.DebugContext(ctx, "KEK rotated successfully", "keyId", opts.KEKid, "dbId", dbID)
	return dbID, opts.KEKid, nil
}

func buildEncryptionBody(data []byte) map[string]any {
	return map[string]any{
		"plaintext": base64.StdEncoding.EncodeToString(data),
	}
}

func (e *Crypto) encrypt(ctx context.Context, requestID string, kekID uuid.UUID, dek []byte) (string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "encrypt",
		RequestID: requestID,
	}).With("kekID", kekID.String())
	logger.DebugContext(ctx, "Encrypting data with KEK...")

	secret, err := e.opLogical.WriteWithContext(ctx, buildKEKPath(e.kekPath, kekID), buildEncryptionBody(dek))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data with KEK: %w", err)
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", errors.New("unexpected response format: missing ciphertext")
	}

	return ciphertext, nil
}

func buildDecryptionBody(ciphertext string) map[string]any {
	return map[string]any{
		"ciphertext": ciphertext,
	}
}

func (e *Crypto) decrypt(
	ctx context.Context,
	requestID string,
	kekID uuid.UUID,
	ciphertext string,
) ([]byte, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "decrypt",
		RequestID: requestID,
	}).With("kekID", kekID.String())
	logger.DebugContext(ctx, "Decrypting data with KEK...")

	secret, err := e.opLogical.WriteWithContext(ctx, buildKEKPath(e.kekPath, kekID), buildDecryptionBody(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data with KEK: %w", err)
	}

	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("unexpected response format: missing plaintext")
	}

	data, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode decrypted data: %w", err)
	}

	return data, nil
}

type encryptDEKOptions struct {
	requestID string
	kekID     uuid.UUID
	dek       []byte
}

func (e *Crypto) encryptDEK(
	ctx context.Context,
	opts encryptDEKOptions,
) (string, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "decryptDEK",
		RequestID: opts.requestID,
	})
	logger.DebugContext(ctx, "Encrypt DEK...")

	dekID := utils.ExtractSecretID(opts.dek)
	ciphertext, err := e.encrypt(ctx, opts.requestID, opts.kekID, opts.dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt DEK", "error", err)
		return "", "", err
	}

	return dekID, ciphertext, nil
}

type decryptDEKOptions struct {
	requestID    string
	encryptedDEK string
	kekID        uuid.UUID
}

func (e *Crypto) decryptDEK(
	ctx context.Context,
	opts decryptDEKOptions,
) ([]byte, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "decryptDEK",
		RequestID: opts.requestID,
	})
	logger.DebugContext(ctx, "Decrypt DEK...")

	dek, err := e.decrypt(ctx, opts.requestID, opts.kekID, opts.encryptedDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return nil, err
	}

	logger.DebugContext(ctx, "DEK decrypted successfully")
	return dek, nil
}
