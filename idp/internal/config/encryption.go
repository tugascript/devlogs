// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type EncryptionConfig struct {
	kekPath string
	dekTTL  int64
	jwkTTL  int64
}

func (ec *EncryptionConfig) KEKPath() string {
	return ec.kekPath
}

func (ec *EncryptionConfig) DEKTTL() int64 {
	return ec.dekTTL
}

func (ec *EncryptionConfig) JWKTTL() int64 {
	return ec.jwkTTL
}

func NewEncryptionConfig(kekPath string, dekTTL, jwkTTL int64) EncryptionConfig {
	return EncryptionConfig{
		kekPath: kekPath,
		dekTTL:  dekTTL,
		jwkTTL:  jwkTTL,
	}
}
