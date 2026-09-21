// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	appsDynamicRegistrationLocation string = "apps_dynamic_registration"

	appsDynamicRegistrationIATPrefix string = "apps_dynamic_registration_iat"
)

func buildAppDynamicRegistrationIATAuthCacheKey(hostname, clientID string) string {
	return fmt.Sprintf("%s:%s:auth:%s", appsDynamicRegistrationIATPrefix, hostname, clientID)
}

type AppsDynamicRegistrationIATAuthData struct {
	AccountID   int32  `json:"account_id"`
	Domain      string `json:"domain"`
	State       string `json:"state"`
	Challenge   string `json:"challenge"`
	RedirectURI string `json:"redirect_uri"`
}

type SaveAppsDynamicRegistrationIATAuthOptions struct {
	RequestID   string
	Hostname    string
	AccountID   int32
	Domain      string
	State       string
	RedirectURI string
	Challenge   string
}

func (c *Cache) SaveAppsDynamicRegistrationIATAuth(
	ctx context.Context,
	opts SaveAppsDynamicRegistrationIATAuthOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  appsDynamicRegistrationLocation,
		Method:    "SaveAppsDynamicRegistrationIATAuth",
		RequestID: opts.RequestID,
	}).With(
		"redirectUri", opts.RedirectURI,
	)
	logger.DebugContext(ctx, "Saving apps dynamic registration IAT sessions...")

	data := AppsDynamicRegistrationIATAuthData{
		AccountID:   opts.AccountID,
		State:       opts.State,
		Domain:      opts.Domain,
		RedirectURI: opts.RedirectURI,
		Challenge:   opts.Challenge,
	}
	return c.appsDynamicRegistration(opts.Hostname).saveAuth(ctx, logger, data)
}

type GetAppsDynamicRegistrationIATAuthOptions struct {
	RequestID string
	Hostname  string
	ClientID  string
}

func (c *Cache) GetAppsDynamicRegistrationAuthIAT(
	ctx context.Context,
	opts GetAppsDynamicRegistrationIATAuthOptions,
) (AppsDynamicRegistrationIATAuthData, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  appsDynamicRegistrationLocation,
		Method:    "GetAppsDynamicRegistrationAuthIAT",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Getting apps dynamic registration IAT...")

	return getDynamicRegistrationAuth[AppsDynamicRegistrationIATAuthData](ctx, c.appsDynamicRegistration(opts.Hostname), logger, opts.ClientID)
}

type DeleteAppsDynamicRegistrationIATAuthOptions struct {
	RequestID string
	Hostname  string
	ClientID  string
}

func (c *Cache) DeleteAppsDynamicRegistrationIATAuth(
	ctx context.Context,
	opts DeleteAppsDynamicRegistrationIATAuthOptions,
) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  appsDynamicRegistrationLocation,
		Method:    "DeleteAppsDynamicRegistrationIATAuth",
		RequestID: opts.RequestID,
	}).With(
		"clientId", opts.ClientID,
	)
	logger.DebugContext(ctx, "Deleting apps dynamic registration IAT...")

	return c.storage.DeleteWithContext(ctx, buildAppDynamicRegistrationIATAuthCacheKey(opts.Hostname, opts.ClientID))
}

type SaveAppsDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	Hostname  string
	ClientID  string
	Domain    string
}

func (c *Cache) SaveAppsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts SaveAppsDynamicRegistrationIATLoginCSRFOptions,
) (string, error) {
	return c.appsDynamicRegistration(opts.Hostname).SaveDynamicRegistrationIATLoginCSRF(ctx, SaveDynamicRegistrationIATLoginCSRFOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
		Domain:    opts.Domain,
	})
}

type VerifyAppsDynamicRegistrationIATLoginCSRFOptions struct {
	RequestID string
	Hostname  string
	ClientID  string
	Domain    string
	CSRFToken string
}

func (c *Cache) VerifyAppsDynamicRegistrationIATLoginCSRF(
	ctx context.Context,
	opts VerifyAppsDynamicRegistrationIATLoginCSRFOptions,
) (bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).VerifyDynamicRegistrationIATLoginCSRF(ctx, VerifyDynamicRegistrationIATLoginCSRFOptions{
		RequestID: opts.RequestID,
		ClientID:  opts.ClientID,
		Domain:    opts.Domain,
		CSRFToken: opts.CSRFToken,
	})
}

type AppsDynamicRegistrationIAT2FAData = DynamicRegistrationIAT2FAData

type SaveAppsDynamicRegistrationIAT2FAOptions struct {
	RequestID       string
	Hostname        string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	RedirectURI     string
	Domain          string
	ClientID        string
	State           string
	TwoFAType       string
	TwoFATTL        int64
}

func (c *Cache) SaveAppsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts SaveAppsDynamicRegistrationIAT2FAOptions,
) (string, error) {
	return c.appsDynamicRegistration(opts.Hostname).SaveDynamicRegistrationIAT2FA(ctx, SaveDynamicRegistrationIAT2FAOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		RedirectURI:     opts.RedirectURI,
		Domain:          opts.Domain,
		ClientID:        opts.ClientID,
		State:           opts.State,
		TwoFAType:       opts.TwoFAType,
		TwoFATTL:        opts.TwoFATTL,
	})
}

type GetAppsDynamicRegistrationIAT2FAOptions struct {
	RequestID string
	Hostname  string
	SessionID string
}

func (c *Cache) GetAppsDynamicRegistrationIAT2FA(
	ctx context.Context,
	opts GetAppsDynamicRegistrationIAT2FAOptions,
) (AppsDynamicRegistrationIAT2FAData, bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).GetDynamicRegistrationIAT2FA(ctx, GetDynamicRegistrationIAT2FAOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
	})
}

type SaveAppsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	Hostname  string
	SessionID string
	TwoFATTL  int64
}

func (c *Cache) SaveAppsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts SaveAppsDynamicRegistrationIAT2FACSRFTokenOptions,
) (string, error) {
	return c.appsDynamicRegistration(opts.Hostname).SaveDynamicRegistrationIAT2FACSRFToken(ctx, SaveDynamicRegistrationIAT2FACSRFTokenOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
		TwoFATTL:  opts.TwoFATTL,
	})
}

type VerifyAppsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	Hostname  string
	SessionID string
	CSRFToken string
}

func (c *Cache) VerifyAppsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts VerifyAppsDynamicRegistrationIAT2FACSRFTokenOptions,
) (bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).VerifyDynamicRegistrationIAT2FACSRFToken(ctx, VerifyDynamicRegistrationIAT2FACSRFTokenOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
		CSRFToken: opts.CSRFToken,
	})
}

type DeleteAppsDynamicRegistrationIAT2FACSRFTokenOptions struct {
	RequestID string
	Hostname  string
	SessionID string
}

func (c *Cache) DeleteAppsDynamicRegistrationIAT2FACSRFToken(
	ctx context.Context,
	opts DeleteAppsDynamicRegistrationIAT2FACSRFTokenOptions,
) error {
	return c.appsDynamicRegistration(opts.Hostname).DeleteDynamicRegistrationIAT2FACSRFToken(ctx, DeleteDynamicRegistrationIAT2FACSRFTokenOptions{
		RequestID: opts.RequestID,
		SessionID: opts.SessionID,
	})
}

type AppsDynamicRegistrationIATCodeData = DynamicRegistrationIATCodeData

type GenerateAppsRegistrationIATCodeOptions struct {
	RequestID       string
	Hostname        string
	ClientID        string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
	Challenge       string
}

func (c *Cache) GenerateAppsRegistrationIATCode(
	ctx context.Context,
	opts GenerateAppsRegistrationIATCodeOptions,
) (string, error) {
	return c.appsDynamicRegistration(opts.Hostname).GenerateDynamicRegistrationIATCode(ctx, GenerateDynamicRegistrationIATCodeOptions{
		RequestID:       opts.RequestID,
		ClientID:        opts.ClientID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		Domain:          opts.Domain,
		Challenge:       opts.Challenge,
	})
}

type VerifyAppsRegistrationIATCodeOptions struct {
	RequestID string
	Hostname  string
	Code      string
}

func (c *Cache) VerifyAppsRegistrationIATCode(
	ctx context.Context,
	opts VerifyAppsRegistrationIATCodeOptions,
) (AppsDynamicRegistrationIATCodeData, bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
	})
}

type AppsDynamicRegistrationSessionData = DynamicRegistrationSessionData

type CreateAppsRegistrationSessionKeyOptions struct {
	RequestID       string
	Hostname        string
	ClientID        string
	Domain          string
	AccountPublicID uuid.UUID
	AccountVersion  int32
}

func (c *Cache) CreateAppsRegistrationSessionKey(
	ctx context.Context,
	opts CreateAppsRegistrationSessionKeyOptions,
) (string, error) {
	return c.appsDynamicRegistration(opts.Hostname).CreateDynamicRegistrationSessionKey(ctx, CreateDynamicRegistrationSessionKeyOptions{
		RequestID:       opts.RequestID,
		ClientID:        opts.ClientID,
		Domain:          opts.Domain,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
	})
}

type VerifyAppsRegistrationSessionKeyOptions struct {
	RequestID  string
	Hostname   string
	Domain     string
	SessionKey string
}

func (c *Cache) VerifyAppsRegistrationSessionKey(
	ctx context.Context,
	opts VerifyAppsRegistrationSessionKeyOptions,
) (AppsDynamicRegistrationSessionData, string, bool, bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).VerifyDynamicRegistrationSessionKey(ctx, VerifyDynamicRegistrationSessionKeyOptions{
		RequestID:  opts.RequestID,
		Domain:     opts.Domain,
		SessionKey: opts.SessionKey,
	})
}

type DeleteAppsRegistrationSessionKeyOptions struct {
	RequestID string
	Hostname  string
	Domain    string
	ClientID  string
}

func (c *Cache) DeleteAppsRegistrationSessionKey(
	ctx context.Context,
	opts DeleteAppsRegistrationSessionKeyOptions,
) error {
	return c.appsDynamicRegistration(opts.Hostname).DeleteDynamicRegistrationSessionKey(ctx, DeleteDynamicRegistrationSessionKeyOptions{
		RequestID: opts.RequestID,
		Domain:    opts.Domain,
		ClientID:  opts.ClientID,
	})
}

type AppsDynamicRegistrationIATExtAuthData = DynamicRegistrationIATExtAuthData

type SaveAppsDynamicRegistrationIATExtAuthOptions struct {
	RequestID    string
	Hostname     string
	ClientID     string
	Domain       string
	Provider     string
	State        string
	RequestState string
}

func (c *Cache) SaveAppsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts SaveAppsDynamicRegistrationIATExtAuthOptions,
) error {
	return c.appsDynamicRegistration(opts.Hostname).SaveDynamicRegistrationIATExtAuth(ctx, SaveDynamicRegistrationIATExtAuthOptions{
		RequestID:    opts.RequestID,
		ClientID:     opts.ClientID,
		Domain:       opts.Domain,
		Provider:     opts.Provider,
		State:        opts.State,
		RequestState: opts.RequestState,
	})
}

type GetAppsDynamicRegistrationIATExtAuthOptions struct {
	RequestID string
	Hostname  string
	Provider  string
	State     string
}

func (c *Cache) GetAppsDynamicRegistrationIATExtAuth(
	ctx context.Context,
	opts GetAppsDynamicRegistrationIATExtAuthOptions,
) (AppsDynamicRegistrationIATExtAuthData, bool, error) {
	return c.appsDynamicRegistration(opts.Hostname).GetDynamicRegistrationIATExtAuth(ctx, GetDynamicRegistrationIATExtAuthOptions{
		RequestID: opts.RequestID,
		Provider:  opts.Provider,
		State:     opts.State,
	})
}

func (c *Cache) appsDynamicRegistration(hostname string) dynamicRegistrationCache {
	return c.dynamicRegistration(appsDynamicRegistrationIATPrefix+":"+hostname, appsDynamicRegistrationLocation)
}
