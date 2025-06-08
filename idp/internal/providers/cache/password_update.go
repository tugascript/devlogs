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

type PasswordUpdatePrefixType string

const (
	passwordUpdatePrefix   string = "password_update"
	passwordUpdateLocation string = "password_update"

	PasswordUpdateAccountPrefix PasswordUpdatePrefixType = "account"
	PasswordUpdateUserPrefix    PasswordUpdatePrefixType = "user"
)

type SaveUpdatePasswordRequestOptions struct {
	RequestID       string
	PrefixType      PasswordUpdatePrefixType
	PublicID        uuid.UUID
	NewPassword     string
	DurationSeconds int64
}

func (c *Cache) SaveUpdatePasswordRequest(ctx context.Context, opts SaveUpdatePasswordRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  passwordUpdateLocation,
		Method:    "SaveUpdatePasswordRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Saving update password request...")

	hashedPassword, err := utils.HashString(opts.NewPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash new password", "error", err)
		return err
	}

	key := fmt.Sprintf("%s:%s:%s", passwordUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte(hashedPassword)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.Set(key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update password request", "error", err)
		return err
	}

	return nil
}

type GetUpdatePasswordRequestOptions struct {
	RequestID  string
	PrefixType PasswordUpdatePrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetUpdatePasswordRequest(ctx context.Context, opts GetUpdatePasswordRequestOptions) (string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  passwordUpdateLocation,
		Method:    "GetUpdatePasswordRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting update password request...")

	key := fmt.Sprintf("%s:%s:%s", passwordUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the update password request", "error", err)
		return "", false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "Update password request not found")
		return "", false, nil
	}

	return string(valByte), true, nil
}
