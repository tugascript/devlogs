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

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	kekLocation string        = "kek"
	kekPrefix   string        = "kek"
	kekDuration time.Duration = 3 * time.Hour
)

func buildKEKKey(prefix string) string {
	return fmt.Sprintf("%s:%s", kekPrefix, prefix)
}

type CacheKEKUUIDOptions struct {
	RequestID string
	KID       uuid.UUID
	Prefix    string
}

func (c *Cache) CacheKEKUUID(ctx context.Context, opts CacheKEKUUIDOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "CacheKEKUUID",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Caching KEK UUID...")

	return c.storage.Set(buildKEKKey(opts.Prefix), opts.KID[:], kekDuration)
}

type GetKEKUUIDOptions struct {
	RequestID string
	Prefix    string
}

func (c *Cache) GetKEKUUID(ctx context.Context, opts GetKEKUUIDOptions) (uuid.UUID, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  kekLocation,
		Method:    "GetKEKUUID",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting KEK UUID...")

	kid, err := c.storage.Get(buildKEKKey(opts.Prefix))
	if err != nil {
		return uuid.Nil, false, err
	}
	if kid == nil {
		return uuid.Nil, false, nil
	}

	return uuid.UUID(kid), true, nil
}
