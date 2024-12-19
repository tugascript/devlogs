package redis

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client     *redis.Client
	pubChannel string
}

func NewRedisClient(client *redis.Client, pubChannel string) *RedisClient {
	return &RedisClient{client: client, pubChannel: pubChannel}
}

func (r *RedisClient) Subscribe(ctx context.Context) *redis.PubSub {
	return r.client.Subscribe(ctx, r.pubChannel)
}

func (r *RedisClient) PublishWithTimeout(ctx context.Context, message string, timeout time.Duration) error {
	// Create a new context with the specified timeout
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() // Ensure the context is canceled to avoid resource leaks

	// Channel to capture the result of publishing
	result := make(chan error, 1)

	go func() {
		// Perform the publish operation and send the result to the channel
		result <- r.client.Publish(ctx, r.pubChannel, message).Err()
	}()

	select {
	case err := <-result:
		// Return the result of the publish operation
		return err
	case <-ctx.Done():
		// If the context times out or is canceled, return the context error
		return ctx.Err()
	}
}
