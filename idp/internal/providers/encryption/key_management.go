// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package encryption

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const keyManagementLocation string = "key_management"

type KeyPair struct {
	KID                 string
	PublicKey           utils.JWK
	encryptedPrivateKey string
}

func (e *KeyPair) EncryptedPrivateKey() string {
	return e.encryptedPrivateKey
}

type GenerateKeyPairOptions struct {
	RequestID  string
	AccountDEK string
	StoredDEK  string
}

type GetPrivateKeyOptions struct {
	RequestID string
	KID       string
}

func encodeEd25519PrivateKeyBytes(privKey ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString([]byte(privKey))
}

func (e *Encryption) GenerateEd25519KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (KeyPair, ed25519.PrivateKey, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateEd25519KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating Ed25519 key pair...")

	dek, accountDEK, isOldKey, err := e.decryptOIDCDEK(ctx, opts.RequestID, opts.StoredDEK, opts.AccountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return KeyPair{}, nil, "", err
	}

	kid := utils.ExtractEd25519KeyID(pub)
	encryptedKey, err := utils.Encrypt(encodeEd25519PrivateKeyBytes(priv), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return KeyPair{}, nil, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	doubleNewDEK, err := utils.Encrypt(newDEK, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt new DEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	publicJwk := utils.EncodeEd25519Jwk(pub, kid)
	return KeyPair{
		KID:                 kid,
		PublicKey:           &publicJwk,
		encryptedPrivateKey: encryptedKey,
	}, priv, doubleNewDEK, nil
}

type DecryptPrivateKeyOptions struct {
	RequestID    string
	EncryptedKey string
	AccountDEK   string
	StoredDEK    string
}

func decodeEd25519PrivateKeyBytes(bytes string) (ed25519.PrivateKey, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(bytes)
	if err != nil {
		return nil, err
	}

	return ed25519.PrivateKey(decodedBytes), nil
}

func (e *Encryption) DecryptEd25519PrivateKey(
	ctx context.Context,
	opts DecryptPrivateKeyOptions,
) (ed25519.PrivateKey, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "DecryptEd25519PrivateKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Decrypt Ed25519 private key...")

	dek, accountDEK, isOldKey, err := e.decryptOIDCDEK(ctx, opts.RequestID, opts.StoredDEK, opts.AccountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return nil, "", err
	}

	base64Key, err := utils.Decrypt(opts.EncryptedKey, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt key", "error", err)
		return nil, "", err
	}

	privKey, err := decodeEd25519PrivateKeyBytes(base64Key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode key", "error", err)
		return nil, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt StoredDEK", "error", err)
		return nil, "", err
	}

	doubleNewDEK, err := utils.Encrypt(newDEK, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt new DEK", "error", err)
		return nil, "", err
	}

	return privKey, doubleNewDEK, nil
}

func encodeES256PrivateKeyBytes(privKey *ecdsa.PrivateKey) string {
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	return fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(privKey.D.Bytes()),
		base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	)
}

func (e *Encryption) GenerateES256KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (KeyPair, *ecdsa.PrivateKey, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateES256KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating ES256 key pair...")

	dek, accountDEK, isOldKey, err := e.decryptOIDCDEK(ctx, opts.RequestID, opts.StoredDEK, opts.AccountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate ES256 private key", "error", err)
		return KeyPair{}, nil, "", err
	}

	kid := utils.ExtractECDSAKeyID(&priv.PublicKey)
	encryptedPrivateKey, err := utils.Encrypt(encodeES256PrivateKeyBytes(priv), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return KeyPair{}, nil, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt StoredDEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	doubleNewDEK, err := utils.Encrypt(newDEK, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt new DEK", "error", err)
		return KeyPair{}, nil, "", err
	}

	publicJwk := utils.EncodeP256Jwk(&priv.PublicKey, kid)
	return KeyPair{
		KID:                 kid,
		PublicKey:           &publicJwk,
		encryptedPrivateKey: encryptedPrivateKey,
	}, priv, doubleNewDEK, nil
}

func decodeES256PrivateKeyBytes(bytes string) (ecdsa.PrivateKey, error) {
	parts := strings.Split(bytes, ".")
	if len(parts) != 3 {
		return ecdsa.PrivateKey{}, fmt.Errorf("invalid key format")
	}

	d, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}

	x, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}

	y, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}

	return ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(d),
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
	}, nil
}

func (e *Encryption) DecryptES256PrivateKey(
	ctx context.Context,
	opts DecryptPrivateKeyOptions,
) (*ecdsa.PrivateKey, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "DecryptES256PrivateKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Decrypt ES256 private key...")

	dek, accountDEK, isOldKey, err := e.decryptOIDCDEK(ctx, opts.RequestID, opts.StoredDEK, opts.AccountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt StoredDEK", "error", err)
		return nil, "", err
	}

	base64Key, err := utils.Decrypt(opts.EncryptedKey, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt key", "error", err)
		return nil, "", err
	}

	privKey, err := decodeES256PrivateKeyBytes(base64Key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode key", "error", err)
		return nil, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.oidcSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt StoredDEK", "error", err)
		return nil, "", err
	}

	doubleNewDEK, err := utils.Encrypt(newDEK, accountDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt new DEK", "error", err)
		return nil, "", err
	}

	return &privKey, doubleNewDEK, nil
}
