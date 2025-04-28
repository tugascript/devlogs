// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
