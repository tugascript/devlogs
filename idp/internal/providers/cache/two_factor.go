// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	twoFactorLocation string = "two_factor"

	twoFactorPrefix     string = "two_factor"
	twoFactorUserPrefix string = "user"
)

func generateCode() (string, error) {
	const codeLength = 6
	const digits = "0123456789"
	code := make([]byte, codeLength)

	for i := 0; i < codeLength; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[num.Int64()]
	}

	return string(code), nil
}

func generateKey(accountID, userID int32) string {
	if userID > 0 {
		return fmt.Sprintf("%s:%d:%s:%d", twoFactorPrefix, accountID, twoFactorUserPrefix, userID)
	}

	return fmt.Sprintf("%s:%d", twoFactorUserPrefix, accountID)
}

type AddTwoFactorCodeOptions struct {
	RequestID string
	AccountID int32
	UserID    int32
	TTL       int64
}

func (c *Cache) AddTwoFactorCode(ctx context.Context, opts AddTwoFactorCodeOptions) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  twoFactorLocation,
		Method:    "AddTwoFactorCode",
		RequestID: opts.RequestID,
	}).With(
		"accountID", opts.AccountID,
		"userID", opts.UserID,
	)
	logger.DebugContext(ctx, "Adding two factor code...")

	code, err := generateCode()
	if err != nil {
		logger.ErrorContext(ctx, "Error generating two factor code", "error", err)
		return "", err
	}

	hashedCode, err := utils.Argon2HashString(code)
	if err != nil {
		logger.ErrorContext(ctx, "Error hashing two factor code", "error", err)
		return "", err
	}

	key := generateKey(opts.AccountID, opts.UserID)
	val := []byte(hashedCode)
	exp := time.Duration(opts.TTL) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error setting two factor code", "error", err)
		return "", err
	}

	return code, nil
}

type VerifyTwoFactorCodeOptions struct {
	RequestID string
	AccountID int32
	UserID    int32
	Code      string
}

func (c *Cache) VerifyTwoFactorCode(ctx context.Context, opts VerifyTwoFactorCodeOptions) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  twoFactorLocation,
		Method:    "VerifyTwoFactorCode",
		RequestID: opts.RequestID,
	}).With(
		"accountID", opts.AccountID,
		"userID", opts.UserID,
	)
	logger.DebugContext(ctx, "Verifying two factor code...")
	key := generateKey(opts.AccountID, opts.UserID)

	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error verifying two factor code", "error", err)
		return false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "Two factor code not found")
		return false, nil
	}

	ok, err := utils.Argon2CompareHash(opts.Code, string(valByte))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare code and its hash")
		return false, err
	}
	if !ok {
		logger.WarnContext(ctx, "Invalid code")
		return false, nil
	}

	if err := c.storage.Delete(key); err != nil {
		logger.ErrorContext(ctx, "Error deleting two factor code", "error", err)
		return true, err
	}

	return true, nil
}
