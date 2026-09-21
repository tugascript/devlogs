// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"

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
	Domain      string `json:"domain"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
}

type SaveAccountCredentialsDynamicRegistrationIATAuthOptions struct {
	Domain      string
	RequestID   string
	State       string
	RedirectURI string
	Challenge   string
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATAuth(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATAuthOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIATAuth",
		RequestID: opts.RequestID,
	}).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT sessions...")

	data := AccountCredentialsDynamicRegistrationIATAuthData{
		State:       opts.State,
		Domain:      opts.Domain,
		RedirectURI: opts.RedirectURI,
		Challenge:   opts.Challenge,
	}
	return c.accountCredentialsDynamicRegistration().saveAuth(ctx, logger, data)
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

	return getDynamicRegistrationAuth[AccountCredentialsDynamicRegistrationIATAuthData](ctx, c.accountCredentialsDynamicRegistration(), logger, opts.ClientID)
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

type SaveAccountCredentialsDynamicRegistrationIATLoginCSRFOptions = SaveDynamicRegistrationIATLoginCSRFOptions

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATLoginCSRFOptions,
) (string, error) {
	return c.accountCredentialsDynamicRegistration().SaveDynamicRegistrationIATLoginCSRF(ctx, opts)
}

type VerifyAccountCredentialsDynamicRegistrationIATLoginCSRFOptions = VerifyDynamicRegistrationIATLoginCSRFOptions

func (c *Cache) VerifyAccountCredentialsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts VerifyAccountCredentialsDynamicRegistrationIATLoginCSRFOptions,
) (bool, error) {
	return c.accountCredentialsDynamicRegistration().VerifyDynamicRegistrationIATLoginCSRF(ctx, opts)
}

type AccountCredentialsDynamicRegistrationIAT2FAData = DynamicRegistrationIAT2FAData

type SaveAccountCredentialsDynamicRegistrationIAT2FAOptions = SaveDynamicRegistrationIAT2FAOptions

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIAT2FAOptions,
) (string, error) {
	return c.accountCredentialsDynamicRegistration().SaveDynamicRegistrationIAT2FA(ctx, opts)
}

type GetAccountCredentialsDynamicRegistrationIAT2FAOptions = GetDynamicRegistrationIAT2FAOptions

func (c *Cache) GetAccountCredentialsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIAT2FAOptions,
) (AccountCredentialsDynamicRegistrationIAT2FAData, bool, error) {
	return c.accountCredentialsDynamicRegistration().GetDynamicRegistrationIAT2FA(ctx, opts)
}

type SaveAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions = SaveDynamicRegistrationIAT2FACSRFTokenOptions

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) (string, error) {
	return c.accountCredentialsDynamicRegistration().SaveDynamicRegistrationIAT2FACSRFToken(ctx, opts)
}

type VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions = VerifyDynamicRegistrationIAT2FACSRFTokenOptions

func (c *Cache) VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) (bool, error) {
	return c.accountCredentialsDynamicRegistration().VerifyDynamicRegistrationIAT2FACSRFToken(ctx, opts)
}

type DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions = DeleteDynamicRegistrationIAT2FACSRFTokenOptions

func (c *Cache) DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) error {
	return c.accountCredentialsDynamicRegistration().DeleteDynamicRegistrationIAT2FACSRFToken(ctx, opts)
}

type AccountCredentialsDynamicRegistrationIATCodeData = DynamicRegistrationIATCodeData

type GenerateAccountCredentialsRegistrationIATCodeOptions = GenerateDynamicRegistrationIATCodeOptions

func (c *Cache) GenerateAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts GenerateAccountCredentialsRegistrationIATCodeOptions,
) (string, error) {
	return c.accountCredentialsDynamicRegistration().GenerateDynamicRegistrationIATCode(ctx, opts)
}

type VerifyAccountCredentialsRegistrationIATCodeOptions = VerifyDynamicRegistrationIATCodeOptions

func (c *Cache) VerifyAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationIATCodeOptions,
) (AccountCredentialsDynamicRegistrationIATCodeData, bool, error) {
	return c.accountCredentialsDynamicRegistration().VerifyDynamicRegistrationIATCode(ctx, opts)
}

type AccountCredentialsDynamicRegistrationSessionData = DynamicRegistrationSessionData

type CreateAccountCredentialsRegistrationSessionKeyOptions = CreateDynamicRegistrationSessionKeyOptions

func (c *Cache) CreateAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationSessionKeyOptions,
) (string, error) {
	return c.accountCredentialsDynamicRegistration().CreateDynamicRegistrationSessionKey(ctx, opts)
}

type VerifyAccountCredentialsRegistrationSessionKeyOptions = VerifyDynamicRegistrationSessionKeyOptions

func (c *Cache) VerifyAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationSessionKeyOptions,
) (AccountCredentialsDynamicRegistrationSessionData, string, bool, bool, error) {
	return c.accountCredentialsDynamicRegistration().VerifyDynamicRegistrationSessionKey(ctx, opts)
}

type DeleteAccountCredentialsRegistrationSessionKeyOptions = DeleteDynamicRegistrationSessionKeyOptions

func (c *Cache) DeleteAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts DeleteAccountCredentialsRegistrationSessionKeyOptions,
) error {
	return c.accountCredentialsDynamicRegistration().DeleteDynamicRegistrationSessionKey(ctx, opts)
}

type AccountCredentialsDynamicRegistrationIATExtAuthData = DynamicRegistrationIATExtAuthData

type SaveAccountCredentialsDynamicRegistrationIATExtAuthOptions = SaveDynamicRegistrationIATExtAuthOptions

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATExtAuthOptions,
) error {
	return c.accountCredentialsDynamicRegistration().SaveDynamicRegistrationIATExtAuth(ctx, opts)
}

type GetAccountCredentialsDynamicRegistrationIATExtAuthOptions = GetDynamicRegistrationIATExtAuthOptions

func (c *Cache) GetAccountCredentialsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIATExtAuthOptions,
) (AccountCredentialsDynamicRegistrationIATExtAuthData, bool, error) {
	return c.accountCredentialsDynamicRegistration().GetDynamicRegistrationIATExtAuth(ctx, opts)
}

func (c *Cache) accountCredentialsDynamicRegistration() dynamicRegistrationCache {
	return c.dynamicRegistration(accountCredentialsDynamicRegistrationIATPrefix, accountCredentialsDynamicRegistrationLocation)
}
