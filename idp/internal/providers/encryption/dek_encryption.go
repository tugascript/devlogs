// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package encryption

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type EncryptWithAccountDEKOptions struct {
	RequestID string
	StoredDEK string
	Text      string
}

func (e *Encryption) EncryptWithAccountDEK(
	ctx context.Context,
	opts EncryptWithAccountDEKOptions,
) (string, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "EncryptWithAccountDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Encrypting with account DEK...")

	dek, isOldKey, err := e.decryptAccountDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return "", "", err
	}

	encryptedText, err := utils.Encrypt(opts.Text, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt text", "error", err)
		return "", "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt DEK", "error", err)
		return "", "", err
	}

	logger.DebugContext(ctx, "Text encrypted successfully")
	return encryptedText, newDEK, nil
}

type DecryptWithAccountDEKOptions struct {
	RequestID     string
	StoredDEK     string
	EncryptedText string
}

func (e *Encryption) DecryptWithAccountDEK(
	ctx context.Context,
	opts DecryptWithAccountDEKOptions,
) (string, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  dekLocation,
		Method:    "DecryptWithAccountDEK",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Decrypting with account DEK...")

	dek, isOldKey, err := e.decryptAccountDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return "", "", err
	}

	decryptedText, err := utils.Decrypt(opts.EncryptedText, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt text", "error", err)
		return "", "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt DEK", "error", err)
		return "", "", err
	}

	logger.DebugContext(ctx, "Text decrypted successfully")
	return decryptedText, newDEK, nil
}
