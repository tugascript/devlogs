// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const cacheResponseLocation string = "cache_response"

type CacheResponseOptions[T any] struct {
	RequestID string
	Key       string
	TTL       int
	Value     T
}

func CacheResponse[T any](
	c *Cache,
	ctx context.Context,
	opts CacheResponseOptions[T],
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  cacheResponseLocation,
		Method:    "CacheResponse",
		RequestID: opts.RequestID,
	}).With("key", opts.Key)
	logger.DebugContext(ctx, "Caching response...")

	responseBytes, err := json.Marshal(opts.Value)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling response", "error", err)
		return "", err
	}

	if err := c.storage.Set(opts.Key, responseBytes, time.Duration(opts.TTL)*time.Second); err != nil {
		logger.ErrorContext(ctx, "Error caching response", "error", err)
		return "", err
	}

	return utils.GenerateETag(responseBytes), nil
}

type GetCachedResponseOptions[T any] struct {
	RequestID string
	Key       string
}

func GetCachedResponse[T any](
	c *Cache,
	ctx context.Context,
	opts GetCachedResponseOptions[T],
) (T, string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  cacheResponseLocation,
		Method:    "GetCachedResponse",
		RequestID: opts.RequestID,
	}).With("key", opts.Key)
	logger.DebugContext(ctx, "Getting cached response...")

	var response T
	responseBytes, err := c.storage.Get(opts.Key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting cached response", "error", err)
		return response, "", err
	}
	if responseBytes == nil {
		logger.DebugContext(ctx, "No cached response found")
		return response, "", nil
	}

	if err := json.Unmarshal(responseBytes, &response); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling response", "error", err)
		return response, "", err
	}

	return response, utils.GenerateETag(responseBytes), nil
}
