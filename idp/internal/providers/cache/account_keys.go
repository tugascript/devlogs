// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountKeysLocation string = "account_keys"

	accountKeyPrefix string = "account_key"
)

type SaveAccountPublicKeyOptions struct {
	RequestID       string
	KID             string
	PublicKey       utils.JWK
	DurationSeconds int64
}

func (c *Cache) SaveAccountPublicKey(ctx context.Context, opts SaveAccountPublicKeyOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  accountKeysLocation,
		Method:    "SaveAccountPublicKey",
		RequestID: opts.RequestID,
	}).With(
		"kid", opts.KID,
	)
	logger.DebugContext(ctx, "Saving account key...")

	key := fmt.Sprintf("%s:%s", accountKeyPrefix, opts.KID)
	val, err := opts.PublicKey.ToJSON()
	if err != nil {
		logger.ErrorContext(ctx, "Error serializing account key", "error", err)
		return err
	}

	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching account key", "error", err)
		return err
	}

	return nil
}

type GetAccountPublicKeyOptions struct {
	RequestID string
	KID       string
}

func (c *Cache) GetAccountPublicKey(ctx context.Context, opts GetAccountPublicKeyOptions) (utils.JWK, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  accountKeysLocation,
		Method:    "GetAccountPublicKey",
		RequestID: opts.RequestID,
	}).With(
		"kid", opts.KID,
	)

	key := fmt.Sprintf("%s:%s", accountKeyPrefix, opts.KID)
	val, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting account key", "error", err)
		return nil, err
	}
	if val == nil {
		logger.DebugContext(ctx, "Account key not found in cache")
		return nil, nil
	}

	var jwk utils.JWK
	if err := json.Unmarshal(val, jwk); err != nil {
		logger.ErrorContext(ctx, "Error deserializing account key", "error", err)
		return nil, err
	}

	return jwk, nil
}
