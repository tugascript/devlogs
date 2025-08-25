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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	dekLocation string = "dek"
	dekPrefix   string = "dek"
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

type SaveEncDEKOptions struct {
	RequestID string
	DEK       string
	KID       string
	KEKid     uuid.UUID
	Suffix    string
}

func (c *Cache) SaveEncDEK(ctx context.Context, opts SaveEncDEKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "SaveEncDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Caching DEK...")

	dekData, err := buildDEKData(opts.KID, opts.DEK, opts.KEKid)
	if err != nil {
		logger.ErrorContext(ctx, "Error building DEK data", "error", err)
		return err
	}

	if err := c.storage.SetWithContext(ctx, buildEncDEKKey(opts.Suffix), dekData, c.dekEncTTL); err != nil {
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

	dekData, err := c.storage.GetWithContext(ctx, buildEncDEKKey(opts.Suffix))
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

func buildDecDEKValue(dek string, kekKID uuid.UUID, expiresAt time.Time) string {
	return fmt.Sprintf("%s::%d::%s", dek, expiresAt.Unix(), kekKID.String())
}

func parseDecDEKValue(data []byte) (string, uuid.UUID, time.Time, error) {
	dataStr := string(data)
	parts := strings.Split(dataStr, "::")
	if len(parts) != 3 {
		return "", uuid.Nil, time.Time{}, errors.New("invalid DEK value")
	}

	unixTime, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return "", uuid.Nil, time.Time{}, err
	}

	kekKID, err := uuid.Parse(parts[2])
	if err != nil {
		return "", uuid.Nil, time.Time{}, err
	}

	return parts[0], kekKID, time.Unix(unixTime, 0), nil
}

type SaveDecDEKOptions struct {
	RequestID string
	DEK       string
	KID       string
	ExpiresAt time.Time
	Prefix    string
	KEKid     uuid.UUID
}

func (c *Cache) SaveDecDEK(ctx context.Context, opts SaveDecDEKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "SaveDecDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Caching DEK...")

	decDEKValue := buildDecDEKValue(opts.DEK, opts.KEKid, opts.ExpiresAt)
	if err := c.storage.SetWithContext(
		ctx,
		buildDecDEKKey(opts.Prefix, opts.KID),
		[]byte(decDEKValue),
		c.dekDecTTL,
	); err != nil {
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

func (c *Cache) GetDecDEK(ctx context.Context, opts GetDecDEKOptions) (string, uuid.UUID, time.Time, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  dekLocation,
		Method:    "GetDecDEK",
		RequestID: opts.RequestID,
	}).With("dekKID", opts.KID)
	logger.DebugContext(ctx, "Getting DEK...")

	dekData, err := c.storage.GetWithContext(ctx, buildDecDEKKey(opts.Prefix, opts.KID))
	if err != nil {
		logger.ErrorContext(ctx, "Error getting DEK", "error", err)
		return "", uuid.Nil, time.Time{}, false, err
	}
	if dekData == nil {
		logger.DebugContext(ctx, "DEK not found")
		return "", uuid.Nil, time.Time{}, false, nil
	}

	dek, kekKID, expiresAt, err := parseDecDEKValue(dekData)
	if err != nil {
		logger.ErrorContext(ctx, "Error parsing DEK data", "error", err)
		return "", uuid.Nil, time.Time{}, false, err
	}

	logger.DebugContext(ctx, "DEK found")
	return dek, kekKID, expiresAt, true, nil
}
