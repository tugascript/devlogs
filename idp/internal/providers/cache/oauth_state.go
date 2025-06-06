// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthStatePrefix   string = "oauth_state"
	oauthStateLocation string = "oauth_state"
)

type AddOAuthStateOptions struct {
	RequestID       string
	State           string
	Provider        string
	DurationSeconds int64
}

func (c *Cache) AddOAuthState(ctx context.Context, opts AddOAuthStateOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Method:    "AddOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding OAuth state...")
	return c.storage.Set(
		oauthStatePrefix+":"+opts.State,
		[]byte(opts.Provider),
		time.Duration(opts.DurationSeconds)*time.Second,
	)
}

func buildUserOAuthStateKey(accountID int32, state, provider string) string {
	return fmt.Sprintf("%s:%s:provider:%s:account:%d", oauthStatePrefix, state, provider, accountID)
}

type AddUserOAuthStateOptions struct {
	RequestID       string
	AccountID       int32
	AppID           int32
	State           string
	Provider        string
	DurationSeconds int64
}

func (c *Cache) AddUserOAuthState(ctx context.Context, opts AddUserOAuthStateOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Method:    "AddUserOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding user OAuth state...")
	return c.storage.Set(
		buildUserOAuthStateKey(opts.AccountID, opts.State, opts.Provider),
		[]byte(strconv.Itoa(int(opts.AppID))),
		time.Duration(opts.DurationSeconds)*time.Second,
	)
}

type VerifyOAuthStateOptions struct {
	RequestID string
	State     string
	Provider  string
}

func (c *Cache) VerifyOAuthState(ctx context.Context, opts VerifyOAuthStateOptions) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Method:    "VerifyOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying OAuth state...")
	valByte, err := c.storage.Get(oauthStatePrefix + ":" + opts.State)

	if err != nil {
		logger.ErrorContext(ctx, "Error verifying OAuth state", "error", err)
		return false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "OAuth state not found")
		return false, nil
	}

	return string(valByte) == opts.Provider, nil
}

type GetOAuthStateAppIDOptions struct {
	RequestID string
	AccountID int32
	State     string
	Provider  string
}

func (c *Cache) GetOAuthStateAppID(ctx context.Context, opts GetOAuthStateAppIDOptions) (int, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  oauthStateLocation,
		Method:    "GetOAuthStateAppID",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying OAuth state...")

	appBytes, err := c.storage.Get(buildUserOAuthStateKey(opts.AccountID, opts.State, opts.Provider))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get OAuth state", "error", err)
		return 0, false, err
	}
	if appBytes == nil {
		logger.WarnContext(ctx, "OAuth state not found")
		return 0, false, nil
	}

	appID, err := strconv.Atoi(string(appBytes))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to convert client ID to int", "error", err)
		return 0, false, err
	}

	return appID, true, nil
}
