package config

type RateLimiterConfig struct {
	max    int64
	expSec int64
}

func NewRateLimiterConfig(max, expSec int64) RateLimiterConfig {
	return RateLimiterConfig{
		max:    max,
		expSec: expSec,
	}
}

func (r *RateLimiterConfig) Max() int64 {
	return r.max
}

func (r *RateLimiterConfig) ExpSec() int64 {
	return r.expSec
}
