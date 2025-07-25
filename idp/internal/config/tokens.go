// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type TokensConfig struct {
	accessTTL             int64
	accountCredentialsTTL int64
	refreshTTL            int64
	confirmTTL            int64
	resetTTL              int64
	oAuthTTL              int64
	twoFATTL              int64
	appsTTL               int64
}

func NewTokensConfig(access, accountCredentials, refresh, confirm, reset, oAuth, twoFA, apps int64) TokensConfig {
	return TokensConfig{
		accessTTL:             access,
		accountCredentialsTTL: accountCredentials,
		refreshTTL:            refresh,
		confirmTTL:            confirm,
		resetTTL:              reset,
		oAuthTTL:              oAuth,
		twoFATTL:              twoFA,
		appsTTL:               apps,
	}
}

// Getters for TokensConfig

func (t TokensConfig) AccessTTL() int64 {
	return t.accessTTL
}

func (t TokensConfig) AccountCredentialsTTL() int64 {
	return t.accountCredentialsTTL
}

func (t TokensConfig) RefreshTTL() int64 {
	return t.refreshTTL
}

func (t TokensConfig) ConfirmTTL() int64 {
	return t.confirmTTL
}

func (t TokensConfig) ResetTTL() int64 {
	return t.resetTTL
}

func (t TokensConfig) OAuthTTL() int64 {
	return t.oAuthTTL
}

func (t TokensConfig) TwoFATTL() int64 {
	return t.twoFATTL
}

func (t TokensConfig) AppsTTL() int64 {
	return t.appsTTL
}
