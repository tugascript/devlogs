package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	maxRetries  = 3
	retryTtlSec = 60
	retryKey    = "retry"
)

func newRetryKey(email string) string {
	return retryKey + ":" + email
}

func (r *RedisClient) Retry(ctx context.Context, email string) (uint, bool, error) {
	key := newRetryKey(email)
	currentRetry, err := r.client.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return 0, false, err
	}
	if currentRetry >= maxRetries {
		return 0, false, nil
	}

	currentRetry++
	if err := r.client.Set(ctx, key, currentRetry, retryTtlSec*time.Second).Err(); err != nil {
		return uint(currentRetry), false, err
	}

	return uint(currentRetry), true, nil
}
