// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	dekLocation string        = "dek"
	dekPrefix   string        = "dek"
	dekDuration time.Duration = 2 * time.Hour
)

func buildEncDEKKey(suffix string) string {
	return fmt.Sprintf("%s:%s", dekPrefix, suffix)
}

type dekData struct {
	DEK    string    `json:"dek"`
	KID    string    `json:"kid"`
	KEKkid uuid.UUID `json:"kek_kid"`
}

func buildDEKData(kid string, encDek string, kekKID uuid.UUID) ([]byte, error) {
	dekData := dekData{
		DEK:    encDek,
		KID:    kid,
		KEKkid: kekKID,
	}
	return json.Marshal(dekData)
}

func parseDEKData(data []byte) (string, string, uuid.UUID, error) {
	var dekData dekData
	if err := json.Unmarshal(data, &dekData); err != nil {
		return "", "", uuid.Nil, err
	}

	return dekData.KID, dekData.DEK, dekData.KEKkid, nil
}

type CacheEncDEKOptions struct {
	RequestID string
	DEK       string
	KID       string
	KEKid     uuid.UUID
	Suffix    string
}

func (c *Cache) CacheEncDEK(ctx context.Context, opts CacheEncDEKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "CacheEncDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Caching DEK...")

	dekData, err := buildDEKData(opts.KID, opts.DEK, opts.KEKid)
	if err != nil {
		logger.ErrorContext(ctx, "Error building DEK data", "error", err)
		return err
	}

	if err := c.storage.Set(buildEncDEKKey(opts.Suffix), dekData, dekDuration); err != nil {
		logger.ErrorContext(ctx, "Error caching DEK", "error", err)
		return err
	}

	logger.DebugContext(ctx, "DEK cached successfully")
	return nil
}

type GetEncDEKOptions struct {
	RequestID string
	Suffix    string
}

func (c *Cache) GetEncDEK(ctx context.Context, opts GetEncDEKOptions) (string, string, uuid.UUID, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "GetEncDEK",
		RequestID: opts.RequestID,
	}).With("suffix", opts.Suffix)
	logger.DebugContext(ctx, "Getting DEK...")

	dekData, err := c.storage.Get(buildEncDEKKey(opts.Suffix))
	if err != nil {
		logger.ErrorContext(ctx, "Error getting DEK", "error", err)
		return "", "", uuid.Nil, false, err
	}
	if dekData == nil {
		logger.DebugContext(ctx, "DEK not found")
		return "", "", uuid.Nil, false, nil
	}

	kid, dek, kekKID, err := parseDEKData(dekData)
	if err != nil {
		logger.ErrorContext(ctx, "Error parsing DEK data", "error", err)
		return "", "", uuid.Nil, false, err
	}

	logger.DebugContext(ctx, "DEK found")
	return kid, dek, kekKID, true, nil
}

func buildDecDEKKey(prefix string, kid string) string {
	return fmt.Sprintf("%s:%s:%s", dekPrefix, prefix, kid)
}

func buildDecDEKValue(dek string, kekKID uuid.UUID) string {
	return fmt.Sprintf("%s::%s", dek, kekKID.String())
}

func parseDecDEKValue(data []byte) (string, uuid.UUID, error) {
	parts := strings.Split(string(data), "::")
	if len(parts) != 2 {
		return "", uuid.Nil, errors.New("invalid DEK value")
	}

	kekKID, err := uuid.Parse(parts[1])
	if err != nil {
		return "", uuid.Nil, err
	}

	return parts[0], kekKID, nil
}

type CacheDecDEKOptions struct {
	RequestID string
	DEK       string
	KID       string
	Prefix    string
	KEKid     uuid.UUID
}

func (c *Cache) CacheDecDEK(ctx context.Context, opts CacheDecDEKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "CacheDecDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Caching DEK...")

	decDEKValue := buildDecDEKValue(opts.DEK, opts.KEKid)
	if err := c.storage.Set(buildDecDEKKey(opts.Prefix, opts.KID), []byte(decDEKValue), dekDuration); err != nil {
		logger.ErrorContext(ctx, "Error caching DEK", "error", err)
		return err
	}

	logger.DebugContext(ctx, "DEK cached successfully")
	return nil
}

type GetDecDEKOptions struct {
	RequestID string
	Prefix    string
	KID       string
}

func (c *Cache) GetDecDEK(ctx context.Context, opts GetDecDEKOptions) (string, uuid.UUID, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "GetDecDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Getting DEK...")

	dekData, err := c.storage.Get(buildDecDEKKey(opts.Prefix, opts.KID))
	if err != nil {
		logger.ErrorContext(ctx, "Error getting DEK", "error", err)
		return "", uuid.Nil, false, err
	}
	if dekData == nil {
		logger.DebugContext(ctx, "DEK not found")
		return "", uuid.Nil, false, nil
	}

	dek, kekKID, err := parseDecDEKValue(dekData)
	if err != nil {
		logger.ErrorContext(ctx, "Error parsing DEK data", "error", err)
		return "", uuid.Nil, false, err
	}

	logger.DebugContext(ctx, "DEK found")
	return dek, kekKID, true, nil
}
