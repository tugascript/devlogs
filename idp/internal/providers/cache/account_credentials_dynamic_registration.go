// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsDynamicRegistrationLocation string = "account_credentials_dynamic_registration"

	accountCredentialsDynamicRegistrationIATPrefix string = "account_credentials_dynamic_registration_iat"
)

func buildAccountCredentialsDynamicRegistrationIATAuthCacheKey(clientID string) string {
	return fmt.Sprintf("%s:auth:%s", accountCredentialsDynamicRegistrationIATPrefix, clientID)
}

type AccountCredentialsDynamicRegistrationIATAuthData struct {
	RedirectURI string `json:"redirect_uri"`
	Challenge   string `json:"challenge"`
	CSRFToken   string `json:"csrf_token"`
	Domain      string `json:"domain"`
	State       string `json:"state"`
}

type SaveAccountCredentialsDynamicRegistrationIATAuthOptions struct {
	RequestID   string
	Challenge   string
	State       string
	RedirectURI string
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATAuth(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATAuthOptions,
) (string, string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIATAuth",
		RequestID: opts.RequestID,
	}).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT sessions...")

	u, err := url.Parse(opts.RedirectURI)
	if err != nil {
		logger.ErrorContext(ctx, "Invalid redirect URI", "error", err)
		return "", "", exceptions.NewValidationError("invalid redirect URI")
	}

	csrfToken, err := utils.GenerateBase64Secret(16)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating CSRF token", "error", err)
		return "", "", err
	}

	data := AccountCredentialsDynamicRegistrationIATAuthData{
		Challenge:   opts.Challenge,
		State:       opts.State,
		Domain:      u.Hostname(),
		RedirectURI: opts.RedirectURI,
		CSRFToken:   utils.Sha256HashHex(csrfToken),
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials dynamic registration IAT data", "error", err)
		return "", "", err
	}

	clientID := utils.Base62UUID()
	return clientID, csrfToken, c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATAuthCacheKey(clientID),
		dataBytes,
		c.oauthStateTTL,
	)
}

type GetAccountCredentialsDynamicRegistrationIATAuthOptions struct {
	RequestID string
	ClientID  string
}

func (c *Cache) GetAccountCredentialsDynamicRegistrationAuthIAT(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIATAuthOptions,
) (AccountCredentialsDynamicRegistrationIATAuthData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "GetAccountCredentialsDynamicRegistrationAuthIAT",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Getting account credentials dynamic registration IAT...")

	data, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIATAuthCacheKey(opts.ClientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return AccountCredentialsDynamicRegistrationIATAuthData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT not found")
		return AccountCredentialsDynamicRegistrationIATAuthData{}, false, nil
	}

	var authData AccountCredentialsDynamicRegistrationIATAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal account credentials dynamic registration IAT data", "error", err)
		return AccountCredentialsDynamicRegistrationIATAuthData{}, false, err
	}

	return authData, true, nil
}

type DeleteAccountCredentialsDynamicRegistrationIATAuthOptions struct {
	RequestID string
	ClientID  string
}

func (c *Cache) DeleteAccountCredentialsDynamicRegistrationIATAuth(
	ctx context.Context,
	opts DeleteAccountCredentialsDynamicRegistrationIATAuthOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "DeleteAccountCredentialsDynamicRegistrationIATAuth",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Deleting account credentials dynamic registration IAT...")

	return c.storage.DeleteWithContext(ctx, buildAccountCredentialsDynamicRegistrationIATAuthCacheKey(opts.ClientID))
}

func buildAccountCredentialsDynamicRegistrationIATCodeCacheKey(codeID string) string {
	return fmt.Sprintf("%s:code:%s", accountCredentialsDynamicRegistrationIATPrefix, codeID)
}

type AccountCredentialsDynamicRegistrationIATCodeData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	Domain          string    `json:"domain"`
	ClientID        string    `json:"client_id"`
	Challenge       string    `json:"challenge"`
	Code            string    `json:"code"`
}

type GenerateAccountCredentialsRegistrationIATCodeOptions struct {
	RequestID       string
	ClientID        string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
	Challenge       string
}

func (c *Cache) GenerateAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts GenerateAccountCredentialsRegistrationIATCodeOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "GenerateAccountCredentialsRegistrationIATCode",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Generating account credentials registration IAT code...")

	codeID := utils.Base62UUID()
	code, err := utils.GenerateBase62Secret(codeByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating OAuth code", "error", err)
		return "", err
	}

	data := AccountCredentialsDynamicRegistrationIATCodeData{
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		Domain:          opts.Domain,
		ClientID:        opts.ClientID,
		Code:            utils.Sha256HashHex(code),
		Challenge:       opts.Challenge,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials registration IAT code data", "error", err)
		return "", err
	}

	if err := c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATCodeCacheKey(codeID),
		dataBytes,
		c.oauthCodeTTL,
	); err != nil {
		logger.ErrorContext(ctx, "Failed to set account credentials registration IAT code in cache", "error", err)
		return "", err
	}

	return fmt.Sprintf("%s-%s", codeID, code), nil
}

type VerifyAccountCredentialsRegistrationIATCodeOptions struct {
	RequestID string
	Code      string
}

func (c *Cache) VerifyAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationIATCodeOptions,
) (AccountCredentialsDynamicRegistrationIATCodeData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "VerifyAccountCredentialsRegistrationIATCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying account credentials registration IAT code...")

	if len(opts.Code) < 45 {
		logger.DebugContext(ctx, "Invalid account credentials registration IAT code length")
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, nil
	}

	parts := strings.Split(opts.Code, "-")
	if len(parts) != 2 {
		logger.WarnContext(ctx, "Invalid account credentials registration IAT code format")
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, nil
	}

	data, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIATCodeCacheKey(parts[0]))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials registration IAT code from cache", "error", err)
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials registration IAT code not found")
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, nil
	}

	var codeData AccountCredentialsDynamicRegistrationIATCodeData
	if err := json.Unmarshal(data, &codeData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal account credentials registration IAT code data", "error", err)
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, err
	}

	ok, err := utils.CompareShaHex(parts[1], codeData.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing OAuth code", "error", err)
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid OAuth code")
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, nil
	}
	if err := c.storage.DeleteWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATCodeCacheKey(parts[0]),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting OAuth code", "error", err)
		return AccountCredentialsDynamicRegistrationIATCodeData{}, false, err
	}
	return codeData, true, nil
}
