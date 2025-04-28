// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthCodePrefix   string = "oauth_code"
	oauthCodeLocation string = "oauth_code"
)

type GenerateOAuthOptions struct {
	RequestID       string
	Email           string
	DurationSeconds int64
}

func (c *Cache) GenerateOAuthCode(ctx context.Context, opts GenerateOAuthOptions) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthCodeLocation,
		Method:    "GenerateOAuthCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating OAuth code...")

	code, err := utils.GenerateBase62Secret(16)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate code", "error", err)
		return "", err
	}

	hashedCode, err := utils.HashString(code)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash code", "error", err)
		return "", err
	}

	key := fmt.Sprintf("%s:%s", oauthCodePrefix, opts.Email)
	val := []byte(hashedCode)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching OAuth code", "error", err)
		return "", err
	}

	return code, nil
}

type VerifyOAuthCodeOptions struct {
	RequestID string
	Email     string
	Code      string
}

func (c *Cache) VerifyOAuthCode(ctx context.Context, opts VerifyOAuthCodeOptions) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthCodeLocation,
		Method:    "VerifyOAuthCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying OAuth code...")

	key := fmt.Sprintf("%s:%s", oauthCodePrefix, opts.Email)
	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting OAuth code", "error", err)
		return false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "OAuth code not found")
		return false, nil
	}

	ok, err := utils.CompareHash(opts.Code, string(valByte))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare code and its hash")
		return false, err
	}
	if !ok {
		logger.WarnContext(ctx, "Invalid code")
		return false, nil
	}

	if err := c.storage.Delete(key); err != nil {
		logger.ErrorContext(ctx, "Error delete OAuth code", "error", err)
		return true, err
	}

	return true, nil
}
