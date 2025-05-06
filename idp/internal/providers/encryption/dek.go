// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package encryption

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const dekLocation string = "dek"

func generateDEK(keyID string, key []byte) ([]byte, string, error) {
	base64DEK, err := utils.GenerateBase64Secret(32)
	if err != nil {
		return nil, "", err
	}

	encryptedDEK, err := utils.Encrypt(base64DEK, key)
	if err != nil {
		return nil, "", err
	}

	dek, err := utils.DecodeBase64Secret(base64DEK)
	if err != nil {
		return nil, "", err
	}

	return dek, fmt.Sprintf("%s:%s", keyID, encryptedDEK), nil
}

func splitDEK(encryptedDEK string) (string, string, error) {
	dekSlice := strings.Split(encryptedDEK, ":")
	if len(dekSlice) != 2 {
		return "", "", errors.New("invalid StoredDEK")
	}

	return dekSlice[0], dekSlice[1], nil
}

type decryptDEKOptions struct {
	storedDEK  string
	secret     *Secret
	oldSecrets map[string][]byte
}

func decryptDEK(
	logger *slog.Logger,
	ctx context.Context,
	opts decryptDEKOptions,
) ([]byte, bool, error) {
	dekID, encryptedDEK, err := splitDEK(opts.storedDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to split StoredDEK", "error", err)
		return nil, false, err
	}

	key := opts.secret.key
	oldKey := dekID != opts.secret.kid
	if oldKey {
		var ok bool
		key, ok = opts.oldSecrets[dekID]
		if !ok {
			logger.ErrorContext(ctx, "StoredDEK key ID not found")
			return nil, false, errors.New("secret key not found")
		}
	}

	base64DEK, err := utils.Decrypt(encryptedDEK, key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return nil, false, err
	}

	dek, err := utils.DecodeBase64Secret(base64DEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode StoredDEK", "error", err)
		return nil, false, err
	}

	return dek, oldKey, nil
}

func reEncryptDEK(isOldKey bool, dek, key []byte) (string, error) {
	if !isOldKey {
		return "", nil
	}

	return utils.Encrypt(base64.RawURLEncoding.EncodeToString(dek), key)
}

func (e *Encryption) decryptAccountDEK(ctx context.Context, requestID, storedDEK string) ([]byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptAccountDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting Account StoredDEK...")
	return decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  storedDEK,
		secret:     &e.accountSecretKey,
		oldSecrets: e.oldSecrets,
	})
}

func (e *Encryption) decryptAppDEK(
	ctx context.Context,
	requestID,
	storedDEK,
	accountDEK string,
) ([]byte, []byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptAppDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting App StoredDEK...")

	decryptedAccountDEK, _, err := e.decryptAccountDEK(ctx, requestID, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt Account StoredDEK", "error", err)
		return nil, nil, false, err
	}

	encryptedDEK, err := utils.Decrypt(storedDEK, decryptedAccountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt App StoredDEK", "error", err)
		return nil, nil, false, err
	}

	dek, isOld, err := decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  encryptedDEK,
		secret:     &e.appSecretKey,
		oldSecrets: e.oldSecrets,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt App StoredDEK", "error", err)
		return nil, nil, false, err
	}

	return dek, decryptedAccountDEK, isOld, nil
}

func (e *Encryption) decryptUserDEK(ctx context.Context, requestID, storedDEK string) ([]byte, bool, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "decryptUserDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Decrypting User StoredDEK...")
	return decryptDEK(logger, ctx, decryptDEKOptions{
		storedDEK:  storedDEK,
		secret:     &e.userSecretKey,
		oldSecrets: e.oldSecrets,
	})
}

func (e *Encryption) GenerateAccountDEK(ctx context.Context, requestID string) (string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "GenerateAccountDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Generate Account StoredDEK...")

	_, encryptedDEK, err := generateDEK(e.accountSecretKey.kid, e.accountSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate the StoredDEK", "error", err)
		return "", err
	}

	return encryptedDEK, nil
}

func (e *Encryption) GenerateAppDEK(ctx context.Context, requestID, accountDEK string) (string, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "GenerateAppDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Generate App StoredDEK...")

	dek, isOldKey, err := e.decryptAccountDEK(ctx, requestID, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt Account StoredDEK", "error", err)
		return "", "", err
	}

	_, encryptedDEK, err := generateDEK(e.appSecretKey.kid, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate the StoredDEK", "error", err)
		return "", "", err
	}

	doubleEncryptedDEK, err := utils.Encrypt(encryptedDEK, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt StoredDEK", "error", err)
		return "", "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt StoredDEK", "error", err)
		return "", "", err
	}

	return doubleEncryptedDEK, newDEK, nil
}

func (e *Encryption) GenerateUserDEK(ctx context.Context, requestID string) (string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "GenerateUserDEK",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Generate User StoredDEK...")

	_, encryptedDEK, err := generateDEK(e.userSecretKey.kid, e.userSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate the StoredDEK", "error", err)
		return "", err
	}

	return encryptedDEK, nil
}
