// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/tokens"

type AuthTokenType string

const (
	AuthTokenTypeAccess            AuthTokenType = "access"
	AuthTokenTypeClientCredentials AuthTokenType = "client_credentials"
	AuthTokenTypeRefresh           AuthTokenType = "refresh"
)

type PurposeTokenType string

const (
	PurposeTokenTypeConfirmation PurposeTokenType = "email_verification"
	PurposeTokenTypeReset        PurposeTokenType = "password_reset"
	PurposeTokenTypeTwoFA        PurposeTokenType = "2fa_code"
)

type IDTokenType string

const IDTokenTypeID IDTokenType = "id"

type TokenPurpose string

const (
	TokenPurpose2FA          TokenPurpose = "2fa"
	TokenPurposeOAuth        TokenPurpose = "oauth"
	TokenPurposeConfirmation TokenPurpose = "confirmation"
	TokenPurposeReset        TokenPurpose = "reset"
)

type Tokens struct {
	logger                 *slog.Logger
	backendDomain          string
	accessTTL              int64
	accountCredentialsTTL  int64
	appsTTL                int64
	refreshTTL             int64
	confirmationTTL        int64
	resetTTL               int64
	twoFATTL               int64
	dynamicRegistrationTTL int64
}

func NewTokens(
	logger *slog.Logger,
	backendDomain string,
	accessTTL int64,
	accountCredentialsTTL int64,
	appsTTL int64,
	refreshTTL int64,
	confirmationTTL int64,
	resetTTL int64,
	twoFATTL int64,
	dynamicRegistrationTTL int64,
) *Tokens {
	return &Tokens{
		logger:                 logger.With(utils.BaseLayer, logLayer),
		accessTTL:              accessTTL,
		accountCredentialsTTL:  accountCredentialsTTL,
		appsTTL:                appsTTL,
		refreshTTL:             refreshTTL,
		confirmationTTL:        confirmationTTL,
		resetTTL:               resetTTL,
		twoFATTL:               twoFATTL,
		backendDomain:          backendDomain,
		dynamicRegistrationTTL: dynamicRegistrationTTL,
	}
}
