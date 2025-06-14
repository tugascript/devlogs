// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// $argon2id$v=19$m={memory},t={iterations},p={parallelism}${salt}${hash}
const argonFormat string = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
const argonMemory uint32 = 65_536
const argonIterations uint32 = 3
const argonParallelism uint8 = 4
const argonKeySize uint32 = 32
const saltSize uint32 = 16

func generateSalt(size uint32) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func Argon2HashString(str string) (string, error) {
	salt, err := generateSalt(saltSize)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(str), salt, argonIterations, argonMemory, argonParallelism, argonKeySize)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)

	fullHash := fmt.Sprintf(argonFormat, argon2.Version, argonMemory, argonIterations, argonParallelism, b64Salt, b64Hash)
	return fullHash, nil
}

func Argon2CompareHash(str, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format: expected 6 parts, got %d", len(parts))
	}

	if parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format: expected argon2id, got %s", parts[1])
	}

	var version uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, fmt.Errorf("failed to parse version: %w", err)
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version: %d", version)
	}

	var mem, iter uint32
	var parallel uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &parallel); err != nil {
		return false, fmt.Errorf("failed to parse memory, iterations, and parallelism: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	comparisonHash := argon2.IDKey([]byte(str), salt, iter, mem, parallel, uint32(len(decodedHash)))
	return bytes.Equal(decodedHash, comparisonHash), nil
}

func Sha256HashHex(bytes []byte) string {
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}

func GenerateETag(bytes []byte) string {
	return `"` + Sha256HashHex(bytes) + `"`
}
