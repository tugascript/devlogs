// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

import "encoding/json"

type EncryptionConfig struct {
	accountSecret string
	oidcSecret    string
	userSecret    string
	oldSecrets    []string
}

func NewEncryptionConfig(accountSecret, oidcSecret, userSecret, oldSecrets string) EncryptionConfig {
	var secretSlice []string
	if err := json.Unmarshal([]byte(oldSecrets), &secretSlice); err != nil {
		panic(err)
	}

	return EncryptionConfig{
		accountSecret: accountSecret,
		oidcSecret:    oidcSecret,
		userSecret:    userSecret,
		oldSecrets:    secretSlice,
	}
}

func (e *EncryptionConfig) AccountSecret() string {
	return e.accountSecret
}

func (e *EncryptionConfig) OIDCSecret() string {
	return e.oidcSecret
}

func (e *EncryptionConfig) UserSecret() string {
	return e.userSecret
}

func (e *EncryptionConfig) OldSecrets() []string {
	return e.oldSecrets
}
