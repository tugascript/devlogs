// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

const memory uint32 = 65_536
const iterations uint32 = 3
const parallelism uint8 = 4
const saltSize uint32 = 16
const keySize uint32 = 32

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func HashString(str string) (string, error) {
	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(str), salt, iterations, memory, parallelism, keySize)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	return b64Salt + "." + b64Hash, nil
}

func CompareHash(str, hash string) (bool, error) {
	parts := strings.Split(hash, ".")

	if len(parts) != 2 {
		return false, nil
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	comparisonHash := argon2.IDKey([]byte(str), salt, iterations, memory, parallelism, keySize)
	return bytes.Equal(decodedHash, comparisonHash), nil
}

func BcryptHashString(str string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(str), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func BcryptCompareHash(str, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(str)); err != nil {
		return false
	}

	return true
}
