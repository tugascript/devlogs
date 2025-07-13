// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type LocalCacheConfig struct {
	counter     int64
	maxCost     int64
	bufferItems int64
	defaultTTL  int64
}

func NewLocalCacheConfig(counter, maxCost, bufferItems, defaultTTL int64) LocalCacheConfig {
	return LocalCacheConfig{
		counter:     counter,
		maxCost:     maxCost,
		bufferItems: bufferItems,
		defaultTTL:  defaultTTL,
	}
}

func (c *LocalCacheConfig) Counter() int64 {
	return c.counter
}

func (c *LocalCacheConfig) MaxCost() int64 {
	return c.maxCost
}

func (c *LocalCacheConfig) BufferItems() int64 {
	return c.bufferItems
}

func (c *LocalCacheConfig) DefaultTTL() int64 {
	return c.defaultTTL
}
