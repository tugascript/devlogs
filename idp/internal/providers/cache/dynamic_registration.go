// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

// dynamicRegistrationCache scopes shared operations to a registration flow.
type dynamicRegistrationCache struct {
	*Cache
	storage  dynamicRegistrationStorage
	prefix   string
	location string
}

type dynamicRegistrationStorage interface {
	GetWithContext(context.Context, string) ([]byte, error)
	SetWithContext(context.Context, string, []byte, time.Duration) error
	DeleteWithContext(context.Context, string) error
}

func (c *Cache) dynamicRegistration(prefix, location string) dynamicRegistrationCache {
	return dynamicRegistrationCache{Cache: c, storage: c.storage, prefix: prefix, location: location}
}

func (c dynamicRegistrationCache) saveAuth(ctx context.Context, logger *slog.Logger, data any) (string, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal dynamic registration auth data", "error", err)
		return "", err
	}
	clientID := utils.Base62UUID()
	return clientID, c.storage.SetWithContext(ctx, c.prefix+":auth:"+clientID, encoded, c.oauthStateTTL)
}

func getDynamicRegistrationAuth[T any](ctx context.Context, c dynamicRegistrationCache, logger *slog.Logger, clientID string) (T, bool, error) {
	var data T
	encoded, err := c.storage.GetWithContext(ctx, c.prefix+":auth:"+clientID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get dynamic registration auth data", "error", err)
		return data, false, err
	}
	if encoded == nil {
		return data, false, nil
	}
	if err := json.Unmarshal(encoded, &data); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal dynamic registration auth data", "error", err)
		var zero T
		return zero, false, err
	}
	return data, true, nil
}

func buildDynamicRegistrationIATLoginCSRFKey(prefix, domain, clientID string) string {
	return fmt.Sprintf("%s:login:%s:%s", prefix, domain, clientID)
}

type SaveDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	ClientID  string
	Domain    string
}

func (c dynamicRegistrationCache) SaveDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts SaveDynamicRegistrationIATLoginCSRFOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "SaveDynamicRegistrationIATLoginCSRF",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Saving dynamic registration IAT login CSRF token...")

	csrfToken, err := utils.GenerateBase64Secret(csrfTokenByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating CSRF token", "error", err)
		return "", err
	}

	return csrfToken, c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationIATLoginCSRFKey(c.prefix, opts.Domain, opts.ClientID),
		[]byte(utils.Sha256HashHex(csrfToken)),
		c.oauthStateTTL,
	)
}

type VerifyDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	ClientID  string
	Domain    string
	CSRFToken string
}

func (c dynamicRegistrationCache) VerifyDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts VerifyDynamicRegistrationIATLoginCSRFOptions,
) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "VerifyDynamicRegistrationIATLoginCSRF",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Verifying dynamic registration IAT login CSRF token...")

	hashedCSRFToken, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationIATLoginCSRFKey(c.prefix, opts.Domain, opts.ClientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get dynamic registration IAT login CSRF token", "error", err)
		return false, err
	}
	if hashedCSRFToken == nil {
		logger.DebugContext(ctx, "dynamic registration IAT login CSRF token not found")
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
		buildDynamicRegistrationIATLoginCSRFKey(c.prefix, opts.Domain, opts.ClientID),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting CSRF token", "error", err)
		return false, err
	}

	return true, nil
}

type DynamicRegistrationIAT2FAData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	RedirectURI     string    `json:"redirect_uri"`
	ClientID        string    `json:"clientId"`
	Domain          string    `json:"domain"`
	State           string    `json:"state"`
	TwoFAType       string    `json:"two_factor_type"`
}

func buildDynamicRegistrationIAT2FACacheKey(prefix, sessionID string) string {
	return fmt.Sprintf("%s:2fa:%s", prefix, utils.Sha256HashHex(sessionID))
}

type SaveDynamicRegistrationIAT2FAOptions struct {
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

func (c dynamicRegistrationCache) SaveDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts SaveDynamicRegistrationIAT2FAOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "SaveDynamicRegistrationIAT2FA",
		RequestID: opts.RequestID,
	}).With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Saving dynamic registration IAT2FA...")

	sessionId := utils.Base64UUID()
	data := DynamicRegistrationIAT2FAData{
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
		logger.ErrorContext(ctx, "Failed to marshal dynamic registration IAT2FA data", "error", err)
		return "", err
	}

	return sessionId, c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationIAT2FACacheKey(c.prefix, sessionId),
		dataBytes,
		time.Duration(opts.TwoFATTL)*time.Second,
	)
}

type GetDynamicRegistrationIAT2FAOptions struct {
	RequestID string
	SessionID string
}

func (c dynamicRegistrationCache) GetDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts GetDynamicRegistrationIAT2FAOptions,
) (DynamicRegistrationIAT2FAData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "GetDynamicRegistrationIAT2FA",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Getting dynamic registration IAT2FA...")

	data, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationIAT2FACacheKey(c.prefix, opts.SessionID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get dynamic registration IAT2FA", "error", err)
		return DynamicRegistrationIAT2FAData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "dynamic registration IAT2FA not found")
		return DynamicRegistrationIAT2FAData{}, false, nil
	}

	var twoFAData DynamicRegistrationIAT2FAData
	if err := json.Unmarshal(data, &twoFAData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal dynamic registration IAT2FA data", "error", err)
		return DynamicRegistrationIAT2FAData{}, false, err
	}

	return twoFAData, true, nil
}

func buildDynamicRegistrationIAT2FACSRFCacheKey(prefix, sessionID string) string {
	return fmt.Sprintf("%s:2fa-csrf:%s", prefix, utils.Sha256HashHex(sessionID))
}

type SaveDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
	TwoFATTL  int64
}

func (c dynamicRegistrationCache) SaveDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts SaveDynamicRegistrationIAT2FACSRFTokenOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "SaveDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Saving dynamic registration IAT2FA CSRF token...")

	csrfToken, err := utils.GenerateBase64Secret(csrfTokenByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating CSRF token", "error", err)
		return "", err
	}

	return csrfToken, c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationIAT2FACSRFCacheKey(c.prefix, opts.SessionID),
		[]byte(utils.Sha256HashHex(csrfToken)),
		time.Duration(opts.TwoFATTL)*time.Second,
	)
}

type VerifyDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
	CSRFToken string
}

func (c dynamicRegistrationCache) VerifyDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts VerifyDynamicRegistrationIAT2FACSRFTokenOptions,
) (bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "VerifyDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	}).With(
		"sessionId", opts.SessionID,
	)
	logger.DebugContext(ctx, "Verifying dynamic registration IAT2FA CSRF token...")

	hashedCSRFToken, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationIAT2FACSRFCacheKey(c.prefix, opts.SessionID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get dynamic registration IAT2FA CSRF token", "error", err)
		return false, err
	}
	if hashedCSRFToken == nil {
		logger.DebugContext(ctx, "dynamic registration IAT2FA CSRF token not found")
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
		buildDynamicRegistrationIAT2FACSRFCacheKey(c.prefix, opts.SessionID),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting CSRF token", "error", err)
		return false, err
	}

	return true, nil
}

type DeleteDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	SessionID string
}

func (c dynamicRegistrationCache) DeleteDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts DeleteDynamicRegistrationIAT2FACSRFTokenOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "DeleteDynamicRegistrationIAT2FACSRFToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Deleting dynamic registration IAT2FA CSRF token...")
	return c.storage.DeleteWithContext(
		ctx,
		buildDynamicRegistrationIAT2FACSRFCacheKey(c.prefix, opts.SessionID),
	)
}

func buildDynamicRegistrationIATCodeCacheKey(prefix, codeID string) string {
	return fmt.Sprintf("%s:code:%s", prefix, codeID)
}

type DynamicRegistrationIATCodeData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	Domain          string    `json:"domain"`
	ClientID        string    `json:"client_id"`
	Challenge       string    `json:"challenge"`
	Code            string    `json:"code"`
}

type GenerateDynamicRegistrationIATCodeOptions struct {
	RequestID       string
	ClientID        string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
	Challenge       string
}

func (c dynamicRegistrationCache) GenerateDynamicRegistrationIATCode(
	ctx context.Context,
	opts GenerateDynamicRegistrationIATCodeOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "GenerateDynamicRegistrationIATCode",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Generating registration IAT code...")

	codeID := utils.Base62UUID()
	code, err := utils.GenerateBase62Secret(codeByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating OAuth code", "error", err)
		return "", err
	}

	data := DynamicRegistrationIATCodeData{
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		Domain:          opts.Domain,
		ClientID:        opts.ClientID,
		Code:            utils.Sha256HashHex(code),
		Challenge:       opts.Challenge,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal registration IAT code data", "error", err)
		return "", err
	}

	if err := c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationIATCodeCacheKey(c.prefix, codeID),
		dataBytes,
		c.oauthCodeTTL,
	); err != nil {
		logger.ErrorContext(ctx, "Failed to set registration IAT code in cache", "error", err)
		return "", err
	}

	return fmt.Sprintf("%s-%s", codeID, code), nil
}

type VerifyDynamicRegistrationIATCodeOptions struct {
	RequestID string
	Code      string
}

func (c dynamicRegistrationCache) VerifyDynamicRegistrationIATCode(
	ctx context.Context,
	opts VerifyDynamicRegistrationIATCodeOptions,
) (DynamicRegistrationIATCodeData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "VerifyDynamicRegistrationIATCode",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying registration IAT code...")

	// Codes are "{base62uuid}-{base62secret}". The secret is unpadded base62 of 16
	// bytes, so total length is often 44 or 45. Reject only structurally invalid values.
	parts := strings.Split(opts.Code, "-")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		logger.WarnContext(ctx, "Invalid registration IAT code format")
		return DynamicRegistrationIATCodeData{}, false, nil
	}

	data, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationIATCodeCacheKey(c.prefix, parts[0]))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get registration IAT code from cache", "error", err)
		return DynamicRegistrationIATCodeData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "registration IAT code not found")
		return DynamicRegistrationIATCodeData{}, false, nil
	}

	var codeData DynamicRegistrationIATCodeData
	if err := json.Unmarshal(data, &codeData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal registration IAT code data", "error", err)
		return DynamicRegistrationIATCodeData{}, false, err
	}

	ok, err := utils.CompareShaHex(parts[1], codeData.Code)
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing OAuth code", "error", err)
		return DynamicRegistrationIATCodeData{}, false, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid OAuth code")
		return DynamicRegistrationIATCodeData{}, false, nil
	}
	if err := c.storage.DeleteWithContext(
		ctx,
		buildDynamicRegistrationIATCodeCacheKey(c.prefix, parts[0]),
	); err != nil {
		logger.ErrorContext(ctx, "Error deleting OAuth code", "error", err)
		return DynamicRegistrationIATCodeData{}, false, err
	}
	return codeData, true, nil
}

type DynamicRegistrationSessionData struct {
	AccountPublicID uuid.UUID `json:"account_public_id"`
	AccountVersion  int32     `json:"account_version"`
	SessionKey      string    `json:"session_key"`
}

func buildDynamicRegistrationSessionCacheKey(prefix, domain string, clientID string) string {
	return fmt.Sprintf("%s:session:%s:%s", prefix, domain, clientID)
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

type CreateDynamicRegistrationSessionKeyOptions struct {
	RequestID       string
	ClientID        string
	Domain          string
	AccountPublicID uuid.UUID
	AccountVersion  int32
}

func (c dynamicRegistrationCache) CreateDynamicRegistrationSessionKey(
	ctx context.Context,
	opts CreateDynamicRegistrationSessionKeyOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "CreateDynamicRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"domain", opts.Domain,
		"accountPublicId", opts.AccountPublicID,
	)
	logger.DebugContext(ctx, "Creating registration session key...")

	sessionKey, err := utils.GenerateBase64Secret(sessionKeyByteLen)
	if err != nil {
		logger.ErrorContext(ctx, "Error generating session key", "error", err)
		return "", err
	}

	data := DynamicRegistrationSessionData{
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		SessionKey:      utils.Sha256HashHex(sessionKey),
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal registration session data", "error", err)
		return "", err
	}

	if err := c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationSessionCacheKey(c.prefix, opts.Domain, opts.ClientID),
		dataBytes,
		c.oauthCodeTTL,
	); err != nil {
		logger.ErrorContext(ctx, "Failed to set registration session in cache", "error", err)
		return "", err
	}

	return formatSessionKey(opts.ClientID, sessionKey), nil
}

type VerifyDynamicRegistrationSessionKeyOptions struct {
	RequestID  string
	Domain     string
	SessionKey string
}

func (c dynamicRegistrationCache) VerifyDynamicRegistrationSessionKey(
	ctx context.Context,
	opts VerifyDynamicRegistrationSessionKeyOptions,
) (DynamicRegistrationSessionData, string, bool, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "VerifyDynamicRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"domain", opts.Domain,
	)
	logger.DebugContext(ctx, "Verifying registration session key...")

	clientID, sessionKey, ok := parseSessionKey(opts.SessionKey)
	if !ok {
		logger.DebugContext(ctx, "Invalid registration session key format")
		return DynamicRegistrationSessionData{}, "", false, false, nil
	}

	data, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationSessionCacheKey(c.prefix, opts.Domain, clientID))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get registration session from cache", "error", err)
		return DynamicRegistrationSessionData{}, "", false, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "registration session not found")
		return DynamicRegistrationSessionData{}, "", false, false, nil
	}

	var sessionData DynamicRegistrationSessionData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal registration session data", "error", err)
		return DynamicRegistrationSessionData{}, "", false, false, err
	}

	ok, err = utils.CompareShaHex(sessionKey, sessionData.SessionKey)
	if err != nil {
		logger.ErrorContext(ctx, "Error comparing session key", "error", err)
		return DynamicRegistrationSessionData{}, "", false, true, err
	}
	if !ok {
		logger.DebugContext(ctx, "Invalid session key")
		return DynamicRegistrationSessionData{}, clientID, false, true, nil
	}

	return sessionData, clientID, true, true, nil
}

type DeleteDynamicRegistrationSessionKeyOptions struct {
	RequestID string
	Domain    string
	ClientID  string
}

func (c dynamicRegistrationCache) DeleteDynamicRegistrationSessionKey(
	ctx context.Context,
	opts DeleteDynamicRegistrationSessionKeyOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "DeleteDynamicRegistrationSessionKey",
		RequestID: opts.RequestID,
	}).With(
		"domain", opts.Domain,
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Deleting registration session key...")

	return c.storage.DeleteWithContext(
		ctx,
		buildDynamicRegistrationSessionCacheKey(c.prefix, opts.Domain, opts.ClientID),
	)
}

func buildDynamicRegistrationIATExtAuthCacheKey(prefix, provider, state string) string {
	return fmt.Sprintf("%s:ext-auth:%s:%s", prefix, provider, utils.Sha256HashHex(state))
}

type DynamicRegistrationIATExtAuthData struct {
	ClientID     string `json:"client_id"`
	Domain       string `json:"domain"`
	RequestState string `json:"request_state"`
}

type SaveDynamicRegistrationIATExtAuthOptions struct {
	RequestID    string
	ClientID     string
	Domain       string
	Provider     string
	State        string
	RequestState string
}

func (c dynamicRegistrationCache) SaveDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts SaveDynamicRegistrationIATExtAuthOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "SaveDynamicRegistrationIATExtAuth",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
		"provider", opts.Provider,
	)
	logger.DebugContext(ctx, "Saving dynamic registration IAT external auth...")

	data := DynamicRegistrationIATExtAuthData{
		ClientID:     opts.ClientID,
		Domain:       opts.Domain,
		RequestState: opts.RequestState,
	}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal dynamic registration IAT external auth data", "error", err)
		return err
	}

	return c.storage.SetWithContext(
		ctx,
		buildDynamicRegistrationIATExtAuthCacheKey(c.prefix, opts.Provider, opts.State),
		dataBytes,
		c.oauthStateTTL,
	)
}

type GetDynamicRegistrationIATExtAuthOptions struct {
	RequestID string
	Provider  string
	State     string
}

func (c dynamicRegistrationCache) GetDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts GetDynamicRegistrationIATExtAuthOptions,
) (DynamicRegistrationIATExtAuthData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  c.location,
		Method:    "GetDynamicRegistrationIATExtAuth",
		RequestID: opts.RequestID,
	}).With(
		"provider", opts.Provider,
	)
	logger.DebugContext(ctx, "Getting dynamic registration IAT external auth...")

	data, err := c.storage.GetWithContext(ctx, buildDynamicRegistrationIATExtAuthCacheKey(c.prefix, opts.Provider, opts.State))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get dynamic registration IAT external auth", "error", err)
		return DynamicRegistrationIATExtAuthData{}, false, err
	}
	if data == nil {
		logger.DebugContext(ctx, "dynamic registration IAT external auth not found")
		return DynamicRegistrationIATExtAuthData{}, false, nil
	}

	var authData DynamicRegistrationIATExtAuthData
	if err := json.Unmarshal(data, &authData); err != nil {
		logger.ErrorContext(ctx, "Failed to unmarshal dynamic registration IAT external auth data", "error", err)
		return DynamicRegistrationIATExtAuthData{}, false, err
	}

	return authData, true, nil
}
