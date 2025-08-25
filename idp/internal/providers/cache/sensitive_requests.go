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

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type SensitiveRequestPrefixType string

const (
	sensitiveRequestsLocation string = "sensitive_requests"

	SensitiveRequestAccountPrefix SensitiveRequestPrefixType = "account"
	SensitiveRequestUserPrefix    SensitiveRequestPrefixType = "user"

	emailUpdatePrefix     string = "email_update"
	passwordUpdatePrefix  string = "password_update"
	deleteAccountPrefix   string = "delete_account"
	twoFactorUpdatePrefix string = "two_factor_update"
	usernameUpdatePrefix  string = "username_update"
)

type SaveUpdateEmailRequestOptions struct {
	RequestID       string
	PrefixType      SensitiveRequestPrefixType
	PublicID        uuid.UUID
	Email           string
	DurationSeconds int64
}

func (c *Cache) SaveUpdateEmailRequest(ctx context.Context, opts SaveUpdateEmailRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
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
	if err := c.storage.SetWithContext(ctx, key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update email request", "error", err)
		return err
	}

	return nil
}

type GetUpdateEmailRequestOptions struct {
	RequestID  string
	PrefixType SensitiveRequestPrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetUpdateEmailRequest(ctx context.Context, opts GetUpdateEmailRequestOptions) (string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "GetUpdateEmailRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting update email request...")

	key := fmt.Sprintf("%s:%s:%s", emailUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	valByte, err := c.storage.GetWithContext(ctx, key)
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

type SaveUpdatePasswordRequestOptions struct {
	RequestID       string
	PrefixType      SensitiveRequestPrefixType
	PublicID        uuid.UUID
	NewPassword     string
	DurationSeconds int64
}

func (c *Cache) SaveUpdatePasswordRequest(ctx context.Context, opts SaveUpdatePasswordRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "SaveUpdatePasswordRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Saving update password request...")

	hashedPassword, err := utils.Argon2HashString(opts.NewPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash new password", "error", err)
		return err
	}

	key := fmt.Sprintf("%s:%s:%s", passwordUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte(hashedPassword)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.SetWithContext(ctx, key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update password request", "error", err)
		return err
	}

	return nil
}

type GetUpdatePasswordRequestOptions struct {
	RequestID  string
	PrefixType SensitiveRequestPrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetUpdatePasswordRequest(ctx context.Context, opts GetUpdatePasswordRequestOptions) (string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "GetUpdatePasswordRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting update password request...")

	key := fmt.Sprintf("%s:%s:%s", passwordUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	valByte, err := c.storage.GetWithContext(ctx, key)
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

type SaveDeleteAccountRequestOptions struct {
	RequestID       string
	PrefixType      SensitiveRequestPrefixType
	PublicID        uuid.UUID
	DurationSeconds int64
}

func (c *Cache) SaveDeleteAccountRequest(ctx context.Context, opts SaveDeleteAccountRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "SaveDeleteAccountRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Saving delete account request...")

	key := fmt.Sprintf("%s:%s:%s", deleteAccountPrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte("1")
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.SetWithContext(ctx, key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching delete account request", "error", err)
		return err
	}

	return nil
}

type GetDeleteAccountRequestOptions struct {
	RequestID  string
	PrefixType SensitiveRequestPrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetDeleteAccountRequest(ctx context.Context, opts GetDeleteAccountRequestOptions) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "GetDeleteAccountRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting delete account request...")

	key := fmt.Sprintf("%s:%s:%s", deleteAccountPrefix, opts.PrefixType, opts.PublicID.String())
	val, err := c.storage.GetWithContext(ctx, key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the delete account request", "error", err)
		return false, err
	}
	if val == nil {
		return false, nil
	}

	return true, nil
}

type SaveTwoFactorUpdateRequestOptions struct {
	RequestID       string
	PrefixType      SensitiveRequestPrefixType
	PublicID        uuid.UUID
	TwoFactorType   database.TwoFactorType
	DurationSeconds int64
}

func (c *Cache) SaveTwoFactorUpdateRequest(ctx context.Context, opts SaveTwoFactorUpdateRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "SaveTwoFactorUpdateRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
		"twoFactorType", opts.TwoFactorType,
	)
	logger.DebugContext(ctx, "Saving two-factor update request...")

	key := fmt.Sprintf("%s:%s:%s", twoFactorUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte(opts.TwoFactorType)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.SetWithContext(ctx, key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching two-factor update request", "error", err)
		return err
	}

	return nil
}

type GetTwoFactorUpdateRequestOptions struct {
	RequestID  string
	PrefixType SensitiveRequestPrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetTwoFactorUpdateRequest(
	ctx context.Context,
	opts GetTwoFactorUpdateRequestOptions,
) (database.TwoFactorType, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "GetTwoFactorUpdateRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting two-factor update request...")

	key := fmt.Sprintf("%s:%s:%s", twoFactorUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val, err := c.storage.GetWithContext(ctx, key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the two-factor update request", "error", err)
		return "", err
	}
	if val == nil {
		logger.DebugContext(ctx, "Two-factor update request not found")
		return "", nil
	}

	return database.TwoFactorType(val), nil
}

type SaveUpdateUsernameRequestOptions struct {
	RequestID       string
	PrefixType      SensitiveRequestPrefixType
	PublicID        uuid.UUID
	Username        string
	DurationSeconds int64
}

func (c *Cache) SaveUpdateUsernameRequest(ctx context.Context, opts SaveUpdateUsernameRequestOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "SaveUpdateUsernameRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
		"username", opts.Username,
	)
	logger.DebugContext(ctx, "Saving update username request...")

	key := fmt.Sprintf("%s:%s:%s", usernameUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val := []byte(opts.Username)
	exp := time.Duration(opts.DurationSeconds) * time.Second
	if err := c.storage.SetWithContext(ctx, key, val, exp); err != nil {
		logger.ErrorContext(ctx, "Error caching update username request", "error", err)
		return err
	}

	return nil
}

type GetUpdateUsernameRequestOptions struct {
	RequestID  string
	PrefixType SensitiveRequestPrefixType
	PublicID   uuid.UUID
}

func (c *Cache) GetUpdateUsernameRequest(ctx context.Context, opts GetUpdateUsernameRequestOptions) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  sensitiveRequestsLocation,
		Method:    "GetUpdateUsernameRequest",
		RequestID: opts.RequestID,
	}).With(
		"prefixType", opts.PrefixType,
		"publicID", opts.PublicID,
	)
	logger.DebugContext(ctx, "Getting update username request...")

	key := fmt.Sprintf("%s:%s:%s", usernameUpdatePrefix, opts.PrefixType, opts.PublicID.String())
	val, err := c.storage.GetWithContext(ctx, key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting the update username request", "error", err)
		return "", err
	}
	if val == nil {
		logger.DebugContext(ctx, "Update username request not found")
		return "", nil
	}

	return string(val), nil
}
