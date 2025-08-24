// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsDynamicRegistrationLocation string = "account_credentials_dynamic_registration"

	accountCredentialsDynamicRegistrationIATPrefix string = "account_credentials_dynamic_registration_iat"
)

func buildAccountCredentialsDynamicRegistrationIATCacheKey(clientID string) string {
	return fmt.Sprintf("%s:%s", accountCredentialsDynamicRegistrationIATPrefix, clientID)
}

func buildAccountCredentialsDynamicRegistrationIATData(accountPublicID uuid.UUID, domain string) []byte {
	return []byte(fmt.Sprintf("%s|%s", accountPublicID.String(), domain))
}

type SaveAccountCredentialsDynamicRegistrationIATOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Domain          string
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIAT(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIAT",
		RequestID: opts.RequestID,
	}).With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT sessions...")
	clientID := utils.Base62UUID()
	return clientID, c.storage.Set(
		buildAccountCredentialsDynamicRegistrationIATCacheKey(clientID),
		buildAccountCredentialsDynamicRegistrationIATData(opts.AccountPublicID, opts.Domain),
		c.oauthCodeTTL,
	)
}

func parseAccountCredentialsDynamicRegistrationIATData(data []byte) (uuid.UUID, string, error) {
	parsedData := strings.Split(string(data), "|")
	if len(parsedData) != 2 {
		return uuid.Nil, "", fmt.Errorf("invalid account credentials dynamic registration IAT data")
	}

	accountPublicID, err := uuid.Parse(parsedData[0])
	if err != nil {
		return uuid.Nil, "", fmt.Errorf("invalid account public ID in account credentials dynamic registration IAT data: %w", err)
	}

	return accountPublicID, parsedData[1], nil
}

type GetAccountCredentialsDynamicRegistrationIATOptions struct {
	RequestID string
	ClientID  string
}

func (c *Cache) GetAccountCredentialsDynamicRegistrationIAT(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIATOptions,
) (bool, uuid.UUID, string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "GetAccountCredentialsDynamicRegistrationIAT",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Getting account credentials dynamic registration IAT...")

	data, err := c.storage.Get(buildAccountCredentialsDynamicRegistrationIATCacheKey(opts.ClientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT", "error", err)
		return false, uuid.Nil, "", err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT not found")
		return false, uuid.Nil, "", nil
	}

	accountPublicID, domain, err := parseAccountCredentialsDynamicRegistrationIATData(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse account credentials dynamic registration IAT data", "error", err)
		return false, uuid.Nil, "", err
	}

	return true, accountPublicID, domain, nil
}
