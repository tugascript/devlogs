// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const jwkLocation string = "jwk"

type KeyPair struct {
	KID         string
	PublicKey   utils.JWK
	CryptoSuite utils.SupportedCryptoSuite
}

func buildPrivateKeyCacheKey(cryptoSuite utils.SupportedCryptoSuite, kid string) string {
	return fmt.Sprintf("jwk:%s:%s", cryptoSuite, kid)
}

type StorePrivateKey = func(dekKid string, cryptoSuite utils.SupportedCryptoSuite, kid, encryptedKey string, pubKey utils.JWK) (int32, *exceptions.ServiceError)

type GenerateKeyPairOptions struct {
	RequestID string
	GetDEKfn  GetDEKtoEncrypt
	StoreFN   StorePrivateKey
}

func encodeEd25519PrivateKeyBytes(privKey ed25519.PrivateKey) string {
	return base64.RawURLEncoding.EncodeToString(privKey)
}

func (e *Crypto) GenerateEd25519KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (KeyPair, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GenerateEd25519KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating Ed25519 key pair...")

	dekID, encryptedDEK, kekID, serviceErr := opts.GetDEKfn()
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get encrypted DEK", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, opts.RequestID, dekID, encryptedDEK, kekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	kid := utils.ExtractEd25519KeyID(pub)
	encryptedKey, err := utils.Encrypt(encodeEd25519PrivateKeyBytes(priv), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	publicJwk := utils.EncodeEd25519Jwk(pub, kid)
	if _, err := opts.StoreFN(dekID, utils.SupportedCryptoSuiteEd25519, kid, encryptedKey, &publicJwk); err != nil {
		logger.ErrorContext(ctx, "Failed to store private key", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	if ok := e.localCache.SetWithTTL(
		buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteEd25519, kid),
		priv,
		0,
		e.jwkTTL,
	); !ok {
		logger.ErrorContext(ctx, "Failed to cache private key", "kid", kid)
		return KeyPair{}, exceptions.NewServerError()

	}
	return KeyPair{
		KID:         kid,
		PublicKey:   &publicJwk,
		CryptoSuite: utils.SupportedCryptoSuiteEd25519,
	}, nil
}

type GetEncryptedJWKPrivKey = func(kid string) (string, utils.SupportedCryptoSuite, error)

func decodeEd25519PrivateKeyBytes(
	bytes string,
) (ed25519.PrivateKey, error) {
	decodedBytes, err := base64.RawURLEncoding.DecodeString(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Ed25519 private key: %w", err)
	}

	if len(decodedBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key size: expected %d, got %d",
			ed25519.PrivateKeySize, len(decodedBytes))
	}

	return decodedBytes, nil
}

func (e *Crypto) getDecryptedEd25519PrivateKey(
	ctx context.Context,
	requestID string,
	dekID string,
	encDEK string,
	kekID KEKID,
	jwkKID string,
	encPrivKey string,
) (ed25519.PrivateKey, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "getDecryptedEd25519PrivateKey",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Getting decrypted Ed25519 private key...")

	cachedKey, found := e.localCache.Get(buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteEd25519, jwkKID))
	if found {
		logger.DebugContext(ctx, "Ed25519 private key found in cache", "jwkKID", jwkKID)
		return cachedKey, nil
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, requestID, dekID, encDEK, kekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return nil, serviceErr
	}

	base64privKey, err := utils.Decrypt(encPrivKey, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", err)
		return nil, exceptions.NewServerError()
	}

	privKey, err := decodeEd25519PrivateKeyBytes(base64privKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode private key", "error", err)
		return nil, exceptions.NewServerError()
	}

	if ok := e.localCache.SetWithTTL(
		buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteEd25519, dekID),
		privKey,
		0,
		e.jwkTTL,
	); !ok {
		logger.ErrorContext(ctx, "Failed to cache private key", "dekID", dekID)
		return nil, exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "Ed25519 private key decrypted and cached", "dekID", dekID)
	return privKey, nil
}

func encodeES256PrivateKeyBytes(privKey *ecdsa.PrivateKey) string {
	pubKey := privKey.Public().(*ecdsa.PublicKey)
	return fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(privKey.D.Bytes()),
		base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes()),
		base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes()),
	)
}

func (e *Crypto) GenerateES256KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (KeyPair, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GenerateES256KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating ES256 key pair...")

	dekID, encryptedDEK, kekID, serviceErr := opts.GetDEKfn()
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, opts.RequestID, dekID, encryptedDEK, kekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate ES256 private key", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	kid := utils.ExtractECDSAKeyID(priv.Public().(*ecdsa.PublicKey))
	encodedPrivateKey := encodeES256PrivateKeyBytes(priv)
	encryptedPrivateKey, err := utils.Encrypt(encodedPrivateKey, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	publicJwk := utils.EncodeP256Jwk(&priv.PublicKey, kid)
	if _, err := opts.StoreFN(dekID, utils.SupportedCryptoSuiteES256, kid, encryptedPrivateKey, &publicJwk); err != nil {
		logger.ErrorContext(ctx, "Failed to store private key", "error", err)
		return KeyPair{}, exceptions.NewServerError()
	}

	if ok := e.localCache.SetWithTTL(
		buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteES256, kid),
		[]byte(encodedPrivateKey),
		0,
		e.jwkTTL,
	); !ok {
		logger.ErrorContext(ctx, "Failed to cache private key", "kid", kid)
		return KeyPair{}, exceptions.NewServerError()
	}

	return KeyPair{
		KID:         kid,
		PublicKey:   &publicJwk,
		CryptoSuite: utils.SupportedCryptoSuiteES256,
	}, nil
}

func decodeES256PrivateKeyBytes(bytes string) (ecdsa.PrivateKey, error) {
	parts := strings.Split(bytes, ".")
	if len(parts) != 3 {
		return ecdsa.PrivateKey{}, errors.New("invalid key format")
	}

	d, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}
	if len(d) == 0 {
		return ecdsa.PrivateKey{}, errors.New("invalid D value in key")
	}

	x, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}
	if len(x) == 0 {
		return ecdsa.PrivateKey{}, errors.New("invalid X value in key")
	}

	y, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return ecdsa.PrivateKey{}, err
	}
	if len(y) == 0 {
		return ecdsa.PrivateKey{}, errors.New("invalid Y value in key")
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

func (e *Crypto) getDecryptedES256PrivateKey(
	ctx context.Context,
	requestID string,
	dekID string,
	encDEK string,
	kekID KEKID,
	jwkKID string,
	encPrivKey string,
) (ecdsa.PrivateKey, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "getDecryptedES256PrivateKey",
		RequestID: requestID,
	})
	logger.DebugContext(ctx, "Getting decrypted ES256 private key...")

	cachedKey, found := e.localCache.Get(buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteES256, dekID))
	if found {
		logger.DebugContext(ctx, "ES256 private key found in cache", "dekID", dekID)
		privKey, err := decodeES256PrivateKeyBytes(string(cachedKey))
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decode private key", "error", err)
			return ecdsa.PrivateKey{}, exceptions.NewServerError()
		}

		return privKey, nil
	}

	dek, serviceErr := e.getDecryptedDEK(ctx, requestID, dekID, encDEK, kekID)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get decrypted DEK", "serviceError", serviceErr)
		return ecdsa.PrivateKey{}, serviceErr
	}

	base64privKey, err := utils.Decrypt(encPrivKey, dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", err)
		return ecdsa.PrivateKey{}, exceptions.NewServerError()
	}

	privKey, err := decodeES256PrivateKeyBytes(base64privKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode private key", "error", err)
		return ecdsa.PrivateKey{}, exceptions.NewServerError()
	}

	if ok := e.localCache.SetWithTTL(
		buildPrivateKeyCacheKey(utils.SupportedCryptoSuiteES256, dekID),
		[]byte(base64privKey),
		0,
		e.jwkTTL,
	); !ok {
		logger.ErrorContext(ctx, "Failed to cache private key", "dekID", dekID)
		return ecdsa.PrivateKey{}, exceptions.NewServerError()
	}

	logger.DebugContext(ctx, "ES256 private key decrypted and cached", "dekID", dekID)
	return privKey, nil
}

type JWKkid = string
type EncryptedJWKPrivKey = string
type GetEncryptedJWK = func(cryptoSuite utils.SupportedCryptoSuite) (JWKkid, EncryptedJWKPrivKey, DEKID, EncryptedDEK, KEKID, *exceptions.ServiceError)

type SignTokenOptions struct {
	RequestID string
	Token     *jwt.Token
	GetJWKfn  GetEncryptedJWK
}

func (e *Crypto) SignToken(
	ctx context.Context,
	opts SignTokenOptions,
) (string, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "SignToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Signing token...")

	switch opts.Token.Method.Alg() {
	case string(utils.SupportedCryptoSuiteEd25519):
		kid, encPrivKey, dekID, encDek, kekID, serviceErr := opts.GetJWKfn(utils.SupportedCryptoSuiteEd25519)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get encrypted ed25519 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		privKey, serviceErr := e.getDecryptedEd25519PrivateKey(ctx, opts.RequestID, dekID, encDek, kekID, kid, encPrivKey)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get decrypted ed25519 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		opts.Token.Header["kid"] = kid
		signedToken, err := opts.Token.SignedString(privKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to sign token", "error", err)
			return "", exceptions.NewServerError()
		}

		return signedToken, nil
	case string(utils.SupportedCryptoSuiteES256):
		kid, encPrivKey, dekID, encDek, kekID, serviceErr := opts.GetJWKfn(utils.SupportedCryptoSuiteES256)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get encrypted ES256 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		privKey, serviceErr := e.getDecryptedES256PrivateKey(ctx, opts.RequestID, dekID, encDek, kekID, kid, encPrivKey)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get decrypted ES256 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		opts.Token.Header["kid"] = kid
		signedToken, err := opts.Token.SignedString(&privKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to sign token", "error", err)
			return "", exceptions.NewServerError()
		}

		return signedToken, nil
	default:
		logger.ErrorContext(ctx, "Unsupported signing method", "method", opts.Token.Method.Alg())
		return "", exceptions.NewServerError()
	}
}
