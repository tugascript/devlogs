package utils

import (
	"time"

	"math/rand"
)

const (
	maxDelay     = time.Second * 45
	initialDelay = time.Microsecond * 100
	maxRandDelay = time.Millisecond * 100
)

func generateRandomDuration() time.Duration {
	return time.Duration(rand.Int63n(int64(maxRandDelay)))
}

// ExponentialTimeout generates timeout durations with exponential backoff
// starting from initialDelay and capped at 1 minute
func ExponentialTimeout(attempt uint) time.Duration {
	delay := initialDelay * (1 << attempt)

	if delay > maxDelay {
		delay = maxDelay
	}

	return delay + generateRandomDuration()
}
