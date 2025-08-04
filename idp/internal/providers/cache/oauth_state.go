// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthStatePrefix   string = "oauth_state"
	oauthStateLocation string = "oauth_state"
)

type SaveOAuthStateDataOptions struct {
	RequestID       string
	State           string
	Provider        string
	RequestState    string
	Challenge       string
	ChallengeMethod string
}

type OAuthStateData struct {
	Provider        string `json:"provider"`
	RequestState    string `json:"request_state"`
	Challenge       string `json:"challenge"`
	ChallengeMethod string `json:"challenge_method"`
}

func (c *Cache) SaveOAuthStateData(ctx context.Context, opts SaveOAuthStateDataOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  oauthStateLocation,
		Method:    "SaveOAuthStateData",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Adding OAuth state...")

	data := OAuthStateData{
		Provider:        opts.Provider,
		RequestState:    opts.RequestState,
		Challenge:       opts.Challenge,
		ChallengeMethod: opts.ChallengeMethod,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling OAuth state data", "error", err)
		return err
	}

	return c.storage.Set(
		oauthStatePrefix+":"+opts.State,
		dataBytes,
		c.oauthStateTTL,
	)
}

type GetOAuthStateOptions struct {
	RequestID string
	State     string
}

func (c *Cache) GetOAuthState(
	ctx context.Context,
	opts GetOAuthStateOptions,
) (OAuthStateData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  oauthStateLocation,
		Method:    "GetOAuthState",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting OAuth state...")
	key := oauthStatePrefix + ":" + opts.State
	valByte, err := c.storage.Get(key)

	if err != nil {
		logger.ErrorContext(ctx, "Error verifying OAuth state", "error", err)
		return OAuthStateData{}, false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "OAuth state not found")
		return OAuthStateData{}, false, nil
	}

	var data OAuthStateData
	if err := json.Unmarshal(valByte, &data); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling OAuth state data", "error", err)
		return OAuthStateData{}, false, err
	}
	if err := c.storage.Delete(key); err != nil {
		logger.ErrorContext(ctx, "Error deleting OAuth state", "error", err)
		return OAuthStateData{}, false, err
	}

	return data, true, nil
}
