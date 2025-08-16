// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type CryptoConfig struct {
	kekPath string
}

func (cc *CryptoConfig) KEKPath() string {
	return cc.kekPath
}

func NewEncryptionConfig(kekPath string) CryptoConfig {
	return CryptoConfig{
		kekPath: kekPath,
	}
}
