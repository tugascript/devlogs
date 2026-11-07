// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const cimdMetadataPrefix = "oauth_cimd_metadata"

func cimdMetadataCacheKey(clientID string) string {
	digest := sha256.Sum256([]byte(clientID))
	return fmt.Sprintf("%s:%s", cimdMetadataPrefix, hex.EncodeToString(digest[:]))
}

func (c *Cache) GetCIMDMetadata(ctx context.Context, clientID string) (*dtos.CIMDClientMetadata, error) {
	data, err := c.storage.GetWithContext(ctx, cimdMetadataCacheKey(clientID))
	if err != nil || data == nil {
		return nil, err
	}
	var metadata dtos.CIMDClientMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func (c *Cache) SetCIMDMetadata(ctx context.Context, clientID string, metadata dtos.CIMDClientMetadata, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	data, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	return c.storage.SetWithContext(ctx, cimdMetadataCacheKey(clientID), data, ttl)
}
