// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"log/slog"
	"time"

	fiberRedis "github.com/gofiber/storage/redis/v3"
	"github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/cache"

type Cache struct {
	logger             *slog.Logger
	storage            *fiberRedis.Storage
	kekTTL             time.Duration
	dekDecTTL          time.Duration
	dekEncTTL          time.Duration
	publicJWKTTL       time.Duration
	privateJWKTTL      time.Duration
	publicJWKsTTL      time.Duration
	accountUsernameTTL time.Duration
	wellKnownTTL       time.Duration
}

func NewCache(
	logger *slog.Logger,
	storage *fiberRedis.Storage,
	kekTTL int64,
	dekDecTTL int64,
	dekEncTTL int64,
	publicJWKTTL int64,
	privateJWKTTL int64,
	publicJWKsTTL int64,
	accountUsernameTTL int64,
	wellKnownTTL int64,
) *Cache {
	return &Cache{
		logger:             logger.With(utils.BaseLayer, logLayer),
		storage:            storage,
		kekTTL:             time.Duration(kekTTL) * time.Second,
		dekDecTTL:          time.Duration(dekDecTTL) * time.Second,
		dekEncTTL:          time.Duration(dekEncTTL) * time.Second,
		publicJWKTTL:       time.Duration(publicJWKTTL) * time.Second,
		privateJWKTTL:      time.Duration(privateJWKTTL) * time.Second,
		publicJWKsTTL:      time.Duration(publicJWKsTTL) * time.Second,
		accountUsernameTTL: time.Duration(accountUsernameTTL) * time.Second,
		wellKnownTTL:       time.Duration(wellKnownTTL) * time.Second,
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
