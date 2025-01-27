package cache

import (
	"log/slog"

	"github.com/gofiber/storage/redis/v3"
)

const logLayer string = "cache"

type Cache struct {
	logger  *slog.Logger
	storage *redis.Storage
}

func NewCache(logger *slog.Logger, storage *redis.Storage) *Cache {
	return &Cache{
		logger:  logger,
		storage: storage,
	}
}

func (c *Cache) ResetCache() error {
	return c.storage.Reset()
}
