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

type Ed25519KeyPair struct {
	Kid                 string
	PublicKey           utils.Ed25519JWK
	encryptedPrivateKey string
}

func (e *Ed25519KeyPair) EncryptedPrivateKey() string {
	return e.encryptedPrivateKey
}

type ES256KeyPair struct {
	Kid                 string
	PublicKey           utils.P256JWK
	encryptedPrivateKey string
}

func (e *ES256KeyPair) EncryptedPrivateKey() string {
	return e.encryptedPrivateKey
}

type GenerateKeyPairOptions struct {
	RequestID string
	AccountID int
	StoredDEK string
}

type GetPrivateKeyOptions struct {
	RequestID string
	AccountID int
	KID       string
}

func (e *Encryption) GenerateEd25519KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (Ed25519KeyPair, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateEd25519KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating Ed25519 key pair...")

	dek, isOldKey, err := e.decryptAppDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return Ed25519KeyPair{}, "", err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return Ed25519KeyPair{}, "", err
	}

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse private key", "error", err)
		return Ed25519KeyPair{}, "", err
	}

	kid := utils.ExtractKeyID(pub)
	encryptedKey, err := utils.Encrypt(base64.StdEncoding.EncodeToString(privKey), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return Ed25519KeyPair{}, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt DEK", "error", err)
		return Ed25519KeyPair{}, "", err
	}

	return Ed25519KeyPair{
		Kid:                 kid,
		PublicKey:           utils.EncodeEd25519Jwk(pub, kid),
		encryptedPrivateKey: encryptedKey,
	}, newDEK, nil
}

type DecryptPrivateKeyOptions struct {
	RequestID    string
	EncryptedKey string
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

	dek, isOldKey, err := e.decryptAppDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
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

	newDEK, err := reEncryptDEK(isOldKey, dek, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt DEK", "error", err)
		return nil, "", err
	}

	return key, newDEK, nil
}

func (e *Encryption) GenerateES256KeyPair(
	ctx context.Context,
	opts GenerateKeyPairOptions,
) (ES256KeyPair, string, error) {
	logger := utils.BuildLogger(e.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateES256KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating ES256 key pair...")

	dek, isOldKey, err := e.decryptAppDEK(ctx, opts.RequestID, opts.StoredDEK)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt DEK", "error", err)
		return ES256KeyPair{}, "", err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate ES256 private key", "error", err)
		return ES256KeyPair{}, "", err
	}

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode ES256 private key", "error", err)
		return ES256KeyPair{}, "", err
	}

	publicKeyValue, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse ES256 public key", "error", err)
		return ES256KeyPair{}, "", err
	}

	kid := utils.ExtractKeyID(publicKeyValue)
	encryptedPrivateKey, err := utils.Encrypt(base64.StdEncoding.EncodeToString(privKey), dek)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encrypt private key", "error", err)
		return ES256KeyPair{}, "", err
	}

	newDEK, err := reEncryptDEK(isOldKey, dek, e.appSecretKey.key)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to re-encrypt DEK", "error", err)
		return ES256KeyPair{}, "", err
	}

	return ES256KeyPair{
		Kid:                 kid,
		PublicKey:           utils.EncodeP256Jwk(&priv.PublicKey, kid),
		encryptedPrivateKey: encryptedPrivateKey,
	}, newDEK, nil
}
