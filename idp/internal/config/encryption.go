// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type CryptoConfig struct {
	kekPath string
	dekTTL  int64
	jwkTTL  int64
}

func (cc *CryptoConfig) KEKPath() string {
	return cc.kekPath
}

func (cc *CryptoConfig) DEKTTL() int64 {
	return cc.dekTTL
}

func (cc *CryptoConfig) JWKTTL() int64 {
	return cc.jwkTTL
}

func NewEncryptionConfig(kekPath string, dekTTL, jwkTTL int64) CryptoConfig {
	return CryptoConfig{
		kekPath: kekPath,
		dekTTL:  dekTTL,
		jwkTTL:  jwkTTL,
	}
}
