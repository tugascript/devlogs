// Copyright (c) 2025 Afonso Barracha
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
	"strings"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	oauthCodePrefix   string = "oauth_code"
	oauthCodeLocation string = "oauth_code"
)

type OAuthCodeData struct {
	Email      string `json:"email"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Provider   string `json:"provider"`
	Challenge  string `json:"challenge"`
	Code       string `json:"code"`
}

type GenerateOAuthCodeOptions struct {
	RequestID  string
	Email      string
	GivenName  string
	FamilyName string
	Provider   string
	Challenge  string
}

func (c *Cache) GenerateOAuthCode(ctx context.Context, opts GenerateOAuthCodeOptions) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  oauthCodeLocation,
		Method:    "GenerateOAuthCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating OAuth code...")

	codeID := utils.Base62UUID()
	code := utils.Base62UUID()
	key := fmt.Sprintf("%s:%s", oauthCodePrefix, codeID)

	data := OAuthCodeData{
		Email:      opts.Email,
		GivenName:  opts.GivenName,
		FamilyName: opts.FamilyName,
		Provider:   opts.Provider,
		Challenge:  opts.Challenge,
		Code:       utils.Sha256HashHex([]byte(code)),
	}
	val, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling OAuth code data", "error", err)
		return "", err
	}

	if err := c.storage.Set(key, val, c.oauthCodeTTL); err != nil {
		logger.ErrorContext(ctx, "Error caching OAuth code", "error", err)
		return "", err
	}

	return fmt.Sprintf("%s-%s", codeID, code), nil
}

type VerifyOAuthCodeOptions struct {
	RequestID string
	Code      string
}

func (c *Cache) VerifyOAuthCode(ctx context.Context, opts VerifyOAuthCodeOptions) (OAuthCodeData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  oauthCodeLocation,
		Method:    "VerifyOAuthCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying OAuth code...")

	if len(opts.Code) < 45 {
		logger.DebugContext(ctx, "Invalid OAuth code length")
		return OAuthCodeData{}, false, nil
	}

	parts := strings.Split(opts.Code, "-")
	if len(parts) != 2 {
		logger.DebugContext(ctx, "Invalid OAuth code")
		return OAuthCodeData{}, false, nil
	}

	key := fmt.Sprintf("%s:%s", oauthCodePrefix, parts[0])
	valByte, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting OAuth code", "error", err)
		return OAuthCodeData{}, false, err
	}
	if valByte == nil {
		logger.DebugContext(ctx, "OAuth code not found")
		return OAuthCodeData{}, false, nil
	}

	var data OAuthCodeData
	if err := json.Unmarshal(valByte, &data); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling OAuth code data", "error", err)
		return OAuthCodeData{}, false, err
	}

	decodedHashedCode, err := hex.DecodeString(data.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Error decoding OAuth code hash", "error", err)
		return OAuthCodeData{}, false, err
	}

	hashedCode := sha256.Sum256([]byte(parts[1]))
	if !utils.CompareSha256(hashedCode[:], decodedHashedCode) {
		logger.DebugContext(ctx, "OAuth code does not match")
		return OAuthCodeData{}, false, nil
	}

	if err := c.storage.Delete(key); err != nil {
		logger.ErrorContext(ctx, "Error delete OAuth code", "error", err)
		return OAuthCodeData{}, false, err
	}

	return data, true, nil
}
