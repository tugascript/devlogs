// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type SingleJwtConfig struct {
	publicKey         string
	privateKey        string
	previousPublicKey string
	ttlSec            int64
}

func NewSingleJwtConfig(publicKey, privateKey, previousPublicKey string, ttlSec int64) SingleJwtConfig {
	return SingleJwtConfig{
		publicKey:         publicKey,
		privateKey:        privateKey,
		previousPublicKey: previousPublicKey,
		ttlSec:            ttlSec,
	}
}

func (s *SingleJwtConfig) PublicKey() string {
	return s.publicKey
}

func (s *SingleJwtConfig) PrivateKey() string {
	return s.privateKey
}

func (s *SingleJwtConfig) TtlSec() int64 {
	return s.ttlSec
}

func (s *SingleJwtConfig) PreviousPublicKey() string {
	return s.previousPublicKey
}

type TokensConfig struct {
	access             SingleJwtConfig
	accountCredentials SingleJwtConfig
	refresh            SingleJwtConfig
	confirm            SingleJwtConfig
	reset              SingleJwtConfig
	oAuth              SingleJwtConfig
	twoFA              SingleJwtConfig
	apps               SingleJwtConfig
}

func NewTokensConfig(
	access SingleJwtConfig,
	accountCredentials SingleJwtConfig,
	refresh SingleJwtConfig,
	confirm SingleJwtConfig,
	reset SingleJwtConfig,
	oAuth SingleJwtConfig,
	twoFA SingleJwtConfig,
	apps SingleJwtConfig,
) TokensConfig {
	return TokensConfig{
		access:             access,
		accountCredentials: accountCredentials,
		refresh:            refresh,
		confirm:            confirm,
		reset:              reset,
		oAuth:              oAuth,
		twoFA:              twoFA,
		apps:               apps,
	}
}

func (t *TokensConfig) Access() SingleJwtConfig {
	return t.access
}

func (t *TokensConfig) AccountCredentials() SingleJwtConfig {
	return t.accountCredentials
}

func (t *TokensConfig) Refresh() SingleJwtConfig {
	return t.refresh
}

func (t *TokensConfig) Confirm() SingleJwtConfig {
	return t.confirm
}

func (t *TokensConfig) Reset() SingleJwtConfig {
	return t.reset
}

func (t *TokensConfig) OAuth() SingleJwtConfig {
	return t.oAuth
}

func (t *TokensConfig) TwoFA() SingleJwtConfig {
	return t.twoFA
}

func (t *TokensConfig) Apps() SingleJwtConfig {
	return t.apps
}
