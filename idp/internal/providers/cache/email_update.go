// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type EmailUpdatePrefixType string

const (
	emailUpdatePrefix   string = "email_update"
	emailUpdateLocation string = "email_update"

	EmailUpdateAccountPrefix EmailUpdatePrefixType = "account"
	EmailUpdateUserPrefix    EmailUpdatePrefixType = "user"
)

type SaveUpdateEmailRequestOptions struct {
	RequestID       string
	PrefixType      EmailUpdatePrefixType
	PublicID        uuid.UUID
	Email           string
	DurationSeconds int64
}

func (c *Cache) SaveUpdateEmailRequest(ctx context.Context, opts SaveUpdateEmailRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  emailUpdateLocation,
		Method:    "SaveUpdateEmailRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Saving update email request...")

	key := fmt.Sprintf("%s:%s:%s", emailUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte(opts.Email)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update email request", "error", err)
		return err
	}

	return nil
}

type GetUpdateEmailRequestOptions struct {
	RequestID  string
	PrefixType EmailUpdatePrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetUpdateEmailRequest(ctx context.Context, opts GetUpdateEmailRequestOptions) (string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  emailUpdateLocation,
		Method:    "GetUpdateEmailRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting update email request...")

	key := fmt.Sprintf("%s:%s:%s", emailUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the update email request", "error", err)
		return "", false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "Update email request not found")
		return "", false, nil
	}

	return string(valByte), true, nil
}
