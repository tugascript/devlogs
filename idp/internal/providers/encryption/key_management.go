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
	"crypto/x509"
	"encoding/base64"

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

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse private key", "error", err)
		return KeyPair{}, nil, "", err
	}

	kid := utils.ExtractKeyID(pub)
	encryptedKey, err := utils.Encrypt(base64.StdEncoding.EncodeToString(privKey), dek)
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

	key, err := base64.StdEncoding.DecodeString(base64Key)
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

	return key, doubleNewDEK, nil
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

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode ES256 private key", "error", err)
		return KeyPair{}, nil, "", err
	}

	publicKeyValue, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse ES256 public key", "error", err)
		return KeyPair{}, nil, "", err
	}

	kid := utils.ExtractKeyID(publicKeyValue)
	encryptedPrivateKey, err := utils.Encrypt(base64.StdEncoding.EncodeToString(privKey), dek)
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

	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode key", "error", err)
		return nil, "", err
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse ES256 private key", "error", err)
		return nil, "", err
	}

	ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		logger.ErrorContext(ctx, "Failed to convert to ES256 private key", "error", "invalid key type")
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

	return ecdsaPrivateKey, doubleNewDEK, nil
}
