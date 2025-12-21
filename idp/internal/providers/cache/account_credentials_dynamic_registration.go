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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsDynamicRegistrationLocation string = "account_credentials_dynamic_registration"

	accountCredentialsDynamicRegistrationIATPrefix string = "account_credentials_dynamic_registration_iat"

	csrfTokenByteLen  int = 16
	sessionKeyByteLen int = 32
)

func buildAccountCredentialsDynamicRegistrationIATAuthCacheKey(clientID string) string {
	return fmt.Sprintf("%s:auth:%s", accountCredentialsDynamicRegistrationIATPrefix, clientID)
}

type AccountCredentialsDynamicRegistrationIATAuthData struct {
	RedirectURI string `json:"redirect_uri"`
	Domain      string `json:"domain"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
	Username    string `json:"username,omitempty"`
}

type SaveAccountCredentialsDynamicRegistrationIATAuthOptions struct {
	Domain      string
	RequestID   string
	State       string
	RedirectURI string
	Challenge   string
	Username    string
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
		Username:    opts.Username,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials dynamic registration IAT data", "error", err)
		return "", err
	}

	clientID := utils.Base62UUID()
	return clientID, c.storage.SetWithContext(
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

func buildAccountCredentialsDynamicRegistrationIATLoginCSRFKey(domain, clientID string) string {
	return fmt.Sprintf("%s:login:%s:%s", accountCredentialsDynamicRegistrationIATPrefix, domain, clientID)
}

type SaveAccountCredentialsDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	ClientID  string
	Domain    string
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATLoginCSRFOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIATLoginCSRF",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT login CSRF token...")

	csrfToken, err := utils.GenerateBase64Secret(csrfTokenByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating CSRF token", "error", err)
		return "", err
	}

	return csrfToken, c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATLoginCSRFKey(opts.Domain, opts.ClientID),
		[]byte(utils.Sha256HashHex(csrfToken)),
		c.oauthStateTTL,
	)
}

type VerifyAccountCredentialsDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	ClientID  string
	Domain    string
	CSRFToken string
}

func (c *Cache) VerifyAccountCredentialsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts VerifyAccountCredentialsDynamicRegistrationIATLoginCSRFOptions,
) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "VerifyAccountCredentialsDynamicRegistrationIATLoginCSRF",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Verifying account credentials dynamic registration IAT login CSRF token...")

	hashedCSRFToken, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIATLoginCSRFKey(opts.Domain, opts.ClientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT login CSRF token", "error", err)
		return false, err
	}
	if hashedCSRFToken == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT login CSRF token not found")
		return false, nil
	}

	ok, err := utils.CompareShaHex(opts.CSRFToken, string(hashedCSRFToken))
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing CSRF token", "error", err)
		return false, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid CSRF token")
		return false, nil
	}
	if err := c.storage.DeleteWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATLoginCSRFKey(opts.Domain, opts.ClientID),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting CSRF token", "error", err)
		return false, err
	}

	return true, nil
}

type AccountCredentialsDynamicRegistrationIAT2FAData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	RedirectURI     string    `json:"redirect_uri"`
	ClientID        string    `json:"clientId"`
	Domain          string    `json:"domain"`
	State           string    `json:"state"`
	TwoFAType       string    `json:"two_factor_type"`
}

func buildAccountCredentialsDynamicRegistrationIAT2FACacheKey(sessionID string) string {
	return fmt.Sprintf("%s:2fa:%s", accountCredentialsDynamicRegistrationIATPrefix, utils.Sha256HashHex(sessionID))
}

type SaveAccountCredentialsDynamicRegistrationIAT2FAOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	RedirectURI     string
	Domain          string
	ClientID        string
	State           string
	TwoFAType       string
	TwoFATTL        int64
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIAT2FAOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIAT2FA",
		RequestID: opts.RequestID,
	}).With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT2FA...")

	sessionId := utils.Base64UUID()
	data := AccountCredentialsDynamicRegistrationIAT2FAData{
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		RedirectURI:     opts.RedirectURI,
		Domain:          opts.Domain,
		ClientID:        opts.ClientID,
		State:           opts.State,
		TwoFAType:       opts.TwoFAType,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials dynamic registration IAT2FA data", "error", err)
		return "", err
	}

	return sessionId, c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIAT2FACacheKey(sessionId),
		dataBytes,
		time.Duration(opts.TwoFATTL)*time.Second,
	)
}

type GetAccountCredentialsDynamicRegistrationIAT2FAOptions struct {
	RequestID string
	SessionID string
}

func (c *Cache) GetAccountCredentialsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIAT2FAOptions,
) (AccountCredentialsDynamicRegistrationIAT2FAData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "GetAccountCredentialsDynamicRegistrationIAT2FA",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Getting account credentials dynamic registration IAT2FA...")

	data, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIAT2FACacheKey(opts.SessionID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT2FA", "error", err)
		return AccountCredentialsDynamicRegistrationIAT2FAData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT2FA not found")
		return AccountCredentialsDynamicRegistrationIAT2FAData{}, false, nil
	}

	var twoFAData AccountCredentialsDynamicRegistrationIAT2FAData
	if err := json.Unmarshal(data, &twoFAData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal account credentials dynamic registration IAT2FA data", "error", err)
		return AccountCredentialsDynamicRegistrationIAT2FAData{}, false, err
	}

	return twoFAData, true, nil
}

func buildAccountCredentialsDynamicRegistrationIAT2FACSRFCacheKey(sessionID string) string {
	return fmt.Sprintf("%s:2fa-csrf:%s", accountCredentialsDynamicRegistrationIATPrefix, utils.Sha256HashHex(sessionID))
}

type SaveAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
	TwoFATTL  int64
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT2FA CSRF token...")

	csrfToken, err := utils.GenerateBase64Secret(csrfTokenByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating CSRF token", "error", err)
		return "", err
	}

	return csrfToken, c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIAT2FACSRFCacheKey(opts.SessionID),
		[]byte(utils.Sha256HashHex(csrfToken)),
		time.Duration(opts.TwoFATTL)*time.Second,
	)
}

type VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
	CSRFToken string
}

func (c *Cache) VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "VerifyAccountCredentialsDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Verifying account credentials dynamic registration IAT2FA CSRF token...")

	hashedCSRFToken, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIAT2FACSRFCacheKey(opts.SessionID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT2FA CSRF token", "error", err)
		return false, err
	}
	if hashedCSRFToken == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT2FA CSRF token not found")
		return false, nil
	}

	ok, err := utils.CompareShaHex(opts.CSRFToken, string(hashedCSRFToken))
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing CSRF token", "error", err)
		return false, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid CSRF token")
		return false, nil
	}
	if err := c.storage.DeleteWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIAT2FACSRFCacheKey(opts.SessionID),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting CSRF token", "error", err)
		return false, err
	}

	return true, nil
}

type DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
}

func (c *Cache) DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFTokenOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "DeleteAccountCredentialsDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Deleting account credentials dynamic registration IAT2FA CSRF token...")
	return c.storage.DeleteWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIAT2FACSRFCacheKey(opts.SessionID),
	)
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
		Method:    "VerifyOAuthDynamicRegistrationIATCode",
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

type AccountCredentialsDynamicRegistrationSessionData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	SessionKey      string    `json:"session_key"`
}

func buildAccountCredentialsDynamicRegistrationSessionCacheKey(domain string, clientID string) string {
	return fmt.Sprintf("%s:session:%s:%s", accountCredentialsDynamicRegistrationIATPrefix, domain, clientID)
}

func formatSessionKey(clientID, sessionKey string) string {
	return fmt.Sprintf("%s.%s", clientID, sessionKey)
}

func parseSessionKey(sessionKey string) (string, string, bool) {
	parts := strings.Split(sessionKey, ".")
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

type CreateAccountCredentialsRegistrationSessionKeyOptions struct {
	RequestID       string
	ClientID        string
	Domain          string
	AccountPublicID uuid.UUID
	AccountVersion  int32
}

func (c *Cache) CreateAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationSessionKeyOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "CreateAccountCredentialsRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
		"accountPublicId", opts.AccountPublicID,
	)
	logger.DebugContext(ctx, "Creating account credentials registration session key...")

	sessionKey, err := utils.GenerateBase64Secret(sessionKeyByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating session key", "error", err)
		return "", err
	}

	data := AccountCredentialsDynamicRegistrationSessionData{
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		SessionKey:      utils.Sha256HashHex(sessionKey),
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials registration session data", "error", err)
		return "", err
	}

	if err := c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationSessionCacheKey(opts.Domain, opts.ClientID),
		dataBytes,
		c.oauthCodeTTL,
	); err != nil {
		logger.ErrorContext(ctx, "Failed to set account credentials registration session in cache", "error", err)
		return "", err
	}

	return formatSessionKey(opts.ClientID, sessionKey), nil
}

type VerifyAccountCredentialsRegistrationSessionKeyOptions struct {
	RequestID  string
	Domain     string
	SessionKey string
}

func (c *Cache) VerifyAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationSessionKeyOptions,
) (AccountCredentialsDynamicRegistrationSessionData, string, bool, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "VerifyAccountCredentialsRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Verifying account credentials registration session key...")

	clientID, sessionKey, ok := parseSessionKey(opts.SessionKey)
	if !ok {
		logger.DebugContext(ctx, "Invalid account credentials registration session key format")
		return AccountCredentialsDynamicRegistrationSessionData{}, "", false, true, nil
	}

	data, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationSessionCacheKey(opts.Domain, clientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials registration session from cache", "error", err)
		return AccountCredentialsDynamicRegistrationSessionData{}, "", false, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials registration session not found")
		return AccountCredentialsDynamicRegistrationSessionData{}, "", false, false, nil
	}

	var sessionData AccountCredentialsDynamicRegistrationSessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal account credentials registration session data", "error", err)
		return AccountCredentialsDynamicRegistrationSessionData{}, "", false, false, err
	}

	ok, err = utils.CompareShaHex(sessionKey, sessionData.SessionKey)
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing session key", "error", err)
		return AccountCredentialsDynamicRegistrationSessionData{}, "", false, false, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid session key")
		return AccountCredentialsDynamicRegistrationSessionData{}, clientID, false, true, nil
	}

	return sessionData, clientID, true, true, nil
}

type DeleteAccountCredentialsRegistrationSessionKeyOptions struct {
	RequestID string
	Domain    string
	ClientID  string
}

func (c *Cache) DeleteAccountCredentialsRegistrationSessionKey(
	ctx context.Context,
	opts DeleteAccountCredentialsRegistrationSessionKeyOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "DeleteAccountCredentialsRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"domain", opts.Domain,
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Deleting account credentials registration session key...")

	return c.storage.DeleteWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationSessionCacheKey(opts.Domain, opts.ClientID),
	)
}

func buildAccountCredentialsDynamicRegistrationIATExtAuthCacheKey(provider, state string) string {
	return fmt.Sprintf("%s:ext-auth:%s:%s", accountCredentialsDynamicRegistrationIATPrefix, provider, utils.Sha256HashHex(state))
}

type AccountCredentialsDynamicRegistrationIATExtAuthData struct {
	ClientID     string `json:"client_id"`
	Domain       string `json:"domain"`
	RequestState string `json:"request_state"`
}

type SaveAccountCredentialsDynamicRegistrationIATExtAuthOptions struct {
	RequestID    string
	ClientID     string
	Domain       string
	Provider     string
	State        string
	RequestState string
}

func (c *Cache) SaveAccountCredentialsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts SaveAccountCredentialsDynamicRegistrationIATExtAuthOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "SaveAccountCredentialsDynamicRegistrationIATExtAuth",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"provider", opts.Provider,
	)
	logger.DebugContext(ctx, "Saving account credentials dynamic registration IAT external auth...")

	data := AccountCredentialsDynamicRegistrationIATExtAuthData{
		ClientID:     opts.ClientID,
		Domain:       opts.Domain,
		RequestState: opts.RequestState,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal account credentials dynamic registration IAT external auth data", "error", err)
		return err
	}

	return c.storage.SetWithContext(
		ctx,
		buildAccountCredentialsDynamicRegistrationIATExtAuthCacheKey(opts.Provider, opts.State),
		dataBytes,
		c.oauthStateTTL,
	)
}

type GetAccountCredentialsDynamicRegistrationIATExtAuthOptions struct {
	RequestID string
	Provider  string
	State     string
}

func (c *Cache) GetAccountCredentialsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts GetAccountCredentialsDynamicRegistrationIATExtAuthOptions,
) (AccountCredentialsDynamicRegistrationIATExtAuthData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  accountCredentialsDynamicRegistrationLocation,
		Method:    "GetAccountCredentialsDynamicRegistrationIATExtAuth",
		RequestID: opts.RequestID,
	}).With(
		"provider", opts.Provider,
	)
	logger.DebugContext(ctx, "Getting account credentials dynamic registration IAT external auth...")

	data, err := c.storage.GetWithContext(ctx, buildAccountCredentialsDynamicRegistrationIATExtAuthCacheKey(opts.Provider, opts.State))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials dynamic registration IAT external auth", "error", err)
		return AccountCredentialsDynamicRegistrationIATExtAuthData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "Account credentials dynamic registration IAT external auth not found")
		return AccountCredentialsDynamicRegistrationIATExtAuthData{}, false, nil
	}

	var authData AccountCredentialsDynamicRegistrationIATExtAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal account credentials dynamic registration IAT external auth data", "error", err)
		return AccountCredentialsDynamicRegistrationIATExtAuthData{}, false, err
	}

	return authData, true, nil
}
