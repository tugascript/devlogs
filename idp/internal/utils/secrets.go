// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

func generateRandomBytes(byteLen int) ([]byte, error) {
	b := make([]byte, byteLen)

	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateBase64Secret(byteLen int) (string, error) {
	randomBytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func DecodeBase64Secret(secret string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func GenerateBase62Secret(byteLen int) (string, error) {
	randomBytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	randomInt := new(big.Int).SetBytes(randomBytes)
	return randomInt.Text(62), nil
}

func GenerateBase32Secret(byteLen int) (string, error) {
	randomBytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes), nil
}

func GenerateHexSecret(byteLen int) (string, error) {
	randomBytes, err := generateRandomBytes(byteLen)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomBytes), nil
}
