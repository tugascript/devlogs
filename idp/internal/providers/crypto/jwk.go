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

type StorePrivateKey = func(dekKid string, cryptoSuite utils.SupportedCryptoSuite, kid, encryptedKey string, pubKey utils.JWK) (int32, *exceptions.ServiceError)

type GenerateKeyPairOptions struct {
	RequestID string
	GetDEKfn  GetDEKtoEncrypt
	StoreFN   StorePrivateKey
}

type getDecryptedPrivateKeyOptions struct {
	requestID        string
	jwkKID           string
	encPrivKey       string
	getDecDEKfn      GetDEKtoDecrypt
	getEncDEKfn      GetDEKtoEncrypt
	storeReEncDataFn StoreReEncryptedData
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

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return KeyPair{}, exceptions.NewInternalServerError()
	}
	defer utils.WipeBytes(ctx, logger, priv)

	dekID, encryptedKey, serviceErr := e.EncryptWithDEK(
		ctx,
		EncryptWithDEKOptions{
			RequestID: opts.RequestID,
			GetDEKfn:  opts.GetDEKfn,
			PlainText: encodeEd25519PrivateKeyBytes(priv),
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	kid := utils.ExtractEd25519KeyID(pub)
	publicJwk := utils.EncodeEd25519Jwk(pub, kid)
	if _, err := opts.StoreFN(dekID, utils.SupportedCryptoSuiteEd25519, kid, encryptedKey, &publicJwk); err != nil {
		logger.ErrorContext(ctx, "Failed to store private key", "error", err)
		return KeyPair{}, exceptions.NewInternalServerError()
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
	opts getDecryptedPrivateKeyOptions,
) (ed25519.PrivateKey, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "getDecryptedEd25519PrivateKey",
		RequestID: opts.requestID,
	}).With("jwkKid", opts.jwkKID)
	logger.DebugContext(ctx, "Getting decrypted Ed25519 private key...")

	base64PrivKey, serviceErr := e.DecryptWithDEK(
		ctx,
		DecryptWithDEKOptions{
			RequestID:              opts.requestID,
			GetDecryptDEKfn:        opts.getDecDEKfn,
			GetEncryptDEKfn:        opts.getEncDEKfn,
			StoreReEncryptedDataFn: opts.storeReEncDataFn,
			Ciphertext:             opts.encPrivKey,
			EntityID:               opts.jwkKID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "serviceError", serviceErr)
		return nil, serviceErr
	}

	privKey, err := decodeEd25519PrivateKeyBytes(base64PrivKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode private key", "error", err)
		return nil, exceptions.NewInternalServerError()
	}

	logger.DebugContext(ctx, "Ed25519 private key decrypted and cached")
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

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate ES256 private key", "error", err)
		return KeyPair{}, exceptions.NewInternalServerError()
	}
	defer utils.WipeES256PrivateKey(ctx, logger, priv)

	encodedPrivateKey := encodeES256PrivateKeyBytes(priv)
	dekID, encryptedPrivateKey, serviceErr := e.EncryptWithDEK(
		ctx,
		EncryptWithDEKOptions{
			RequestID: opts.RequestID,
			GetDEKfn:  opts.GetDEKfn,
			PlainText: encodedPrivateKey,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "serviceError", serviceErr)
		return KeyPair{}, serviceErr
	}

	kid := utils.ExtractECDSAKeyID(priv.Public().(*ecdsa.PublicKey))
	publicJwk := utils.EncodeP256Jwk(&priv.PublicKey, kid)
	if _, err := opts.StoreFN(dekID, utils.SupportedCryptoSuiteES256, kid, encryptedPrivateKey, &publicJwk); err != nil {
		logger.ErrorContext(ctx, "Failed to store private key", "error", err)
		return KeyPair{}, exceptions.NewInternalServerError()
	}

	return KeyPair{
		KID:         kid,
		PublicKey:   &publicJwk,
		CryptoSuite: utils.SupportedCryptoSuiteES256,
	}, nil
}

func decodeES256PrivateKeyBytes(bytes string) (*ecdsa.PrivateKey, error) {
	parts := strings.Split(bytes, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid key format")
	}

	d, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	if len(d) == 0 {
		return nil, errors.New("invalid D value in key")
	}

	x, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	if len(x) == 0 {
		return nil, errors.New("invalid X value in key")
	}

	y, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if len(y) == 0 {
		return nil, errors.New("invalid Y value in key")
	}

	return &ecdsa.PrivateKey{
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
	opts getDecryptedPrivateKeyOptions,
) (*ecdsa.PrivateKey, *exceptions.ServiceError) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "getDecryptedES256PrivateKey",
		RequestID: opts.requestID,
	}).With("jwkKID", opts.jwkKID)
	logger.DebugContext(ctx, "Getting decrypted ES256 private key...")

	base64PrivKey, serviceErr := e.DecryptWithDEK(
		ctx,
		DecryptWithDEKOptions{
			RequestID:              opts.requestID,
			GetDecryptDEKfn:        opts.getDecDEKfn,
			GetEncryptDEKfn:        opts.getEncDEKfn,
			StoreReEncryptedDataFn: opts.storeReEncDataFn,
			Ciphertext:             opts.encPrivKey,
			EntityID:               opts.jwkKID,
		},
	)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "serviceError", serviceErr)
		return nil, serviceErr
	}

	privKey, err := decodeES256PrivateKeyBytes(base64PrivKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode private key", "error", err)
		return nil, exceptions.NewInternalServerError()
	}

	logger.DebugContext(ctx, "ES256 private key decrypted and cached")
	return privKey, nil
}

type JWKkid = string
type GetEncryptedJWK = func(cryptoSuite utils.SupportedCryptoSuite) (JWKkid, DEKCiphertext, *exceptions.ServiceError)

type SignTokenOptions struct {
	RequestID       string
	Token           *jwt.Token
	GetJWKfn        GetEncryptedJWK
	GetDecryptDEKfn GetDEKtoDecrypt
	GetEncryptDEKfn GetDEKtoEncrypt
	StoreFN         StoreReEncryptedData
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
		kid, encPrivKey, serviceErr := opts.GetJWKfn(utils.SupportedCryptoSuiteEd25519)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get encrypted ed25519 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		privKey, serviceErr := e.getDecryptedEd25519PrivateKey(ctx, getDecryptedPrivateKeyOptions{
			requestID:        opts.RequestID,
			jwkKID:           kid,
			encPrivKey:       encPrivKey,
			getDecDEKfn:      opts.GetDecryptDEKfn,
			getEncDEKfn:      opts.GetEncryptDEKfn,
			storeReEncDataFn: opts.StoreFN,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get decrypted ed25519 private key", "serviceError", serviceErr)
			return "", serviceErr
		}
		defer utils.WipeBytes(ctx, logger, privKey)

		opts.Token.Header["kid"] = kid
		signedToken, err := opts.Token.SignedString(privKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to sign token", "error", err)
			return "", exceptions.NewInternalServerError()
		}

		return signedToken, nil
	case string(utils.SupportedCryptoSuiteES256):
		kid, encPrivKey, serviceErr := opts.GetJWKfn(utils.SupportedCryptoSuiteES256)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get encrypted ES256 private key", "serviceError", serviceErr)
			return "", serviceErr
		}

		privKey, serviceErr := e.getDecryptedES256PrivateKey(ctx, getDecryptedPrivateKeyOptions{
			requestID:        opts.RequestID,
			jwkKID:           kid,
			encPrivKey:       encPrivKey,
			getDecDEKfn:      opts.GetDecryptDEKfn,
			getEncDEKfn:      opts.GetEncryptDEKfn,
			storeReEncDataFn: opts.StoreFN,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get decrypted ES256 private key", "serviceError", serviceErr)
			return "", serviceErr
		}
		defer utils.WipeES256PrivateKey(ctx, logger, privKey)

		opts.Token.Header["kid"] = kid
		signedToken, err := opts.Token.SignedString(privKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to sign token", "error", err)
			return "", exceptions.NewInternalServerError()
		}

		return signedToken, nil
	default:
		logger.ErrorContext(ctx, "Unsupported signing method", "method", opts.Token.Method.Alg())
		return "", exceptions.NewInternalServerError()
	}
}
