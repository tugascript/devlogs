package cache

import (
	"log/slog"

	"github.com/gofiber/storage/redis/v3"
)

const logLayer string = "cache"

type Cache struct {
	log     *slog.Logger
	storage *redis.Storage
}

func NewCache(log *slog.Logger, storage *redis.Storage) *Cache {
	return &Cache{
		log:     log,
		storage: storage,
	}
}

func (c *Cache) ResetCache() error {
	return c.storage.Reset()
}
