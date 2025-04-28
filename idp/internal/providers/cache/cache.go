// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"log/slog"

	fiberRedis "github.com/gofiber/storage/redis/v3"
	"github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/cache"

type Cache struct {
	logger  *slog.Logger
	storage *fiberRedis.Storage
}

func NewCache(logger *slog.Logger, storage *fiberRedis.Storage) *Cache {
	return &Cache{
		logger:  logger,
		storage: storage,
	}
}

func (c *Cache) ResetCache() error {
	return c.storage.Reset()
}

func (c *Cache) Client() redis.UniversalClient {
	return c.storage.Conn()
}

func (c *Cache) Ping(ctx context.Context) error {
	return c.Client().Ping(ctx).Err()
}
