package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"log/slog"

	infisical "github.com/infisical/go-sdk"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	keyManagementLocation string = "key_management"

	kmsBasePath string = "auth/jwt/keys"
)

type Ed25519KeyPair struct {
	Kid       string
	PublicKey utils.Ed25519JWK
}

type ES256KeyPair struct {
	Kid       string
	PublicKey utils.P256JWK
}

type GenerateKeyPairOptions struct {
	RequestID string
	AccountID int
}

type GetPrivateKeyOptions struct {
	RequestID string
	AccountID int
	KID       string
}

func (v *Vault) GenerateEd25519KeyPair(ctx context.Context, opts GenerateKeyPairOptions) (Ed25519KeyPair, error) {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateEd25519KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating Ed25519 key pair...")

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return Ed25519KeyPair{}, err
	}

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse private key", "error", err)
		return Ed25519KeyPair{}, err
	}

	kid := utils.ExtractKeyID(pub)
	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	if _, err := v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   kid,
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, opts.AccountID),
		SecretValue: privKeyBase64,
		Environment: v.env,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create private key secret", "error", err)
		return Ed25519KeyPair{}, err
	}

	return Ed25519KeyPair{
		Kid:       kid,
		PublicKey: utils.EncodeEd25519Jwk(pub, kid),
	}, nil
}

func (v *Vault) getDecodedPrivateKey(
	logger *slog.Logger,
	ctx context.Context,
	opts GetPrivateKeyOptions,
) (interface{}, error) {
	secret, err := v.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, opts.AccountID),
		SecretKey:   opts.KID,
		Environment: v.env,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find key", "error", err)
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(secret.SecretValue)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode key", "error", err)
		return nil, err
	}

	privateKeyData, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse key", "error", err)
		return nil, err
	}

	return privateKeyData, nil
}

func (v *Vault) GetEd25519PrivateKey(ctx context.Context, opts GetPrivateKeyOptions) (ed25519.PrivateKey, error) {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GetEd25519KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting Ed25519 private key...")

	privateKeyData, err := v.getDecodedPrivateKey(logger, ctx, opts)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyData.(ed25519.PrivateKey)
	if !ok {
		logger.ErrorContext(ctx, "Key is not a valid Ed25519 private key")
		return nil, fmt.Errorf("invalid private key")
	}

	return privateKey, nil
}

func (v *Vault) GenerateES256KeyPair(ctx context.Context, opts GenerateKeyPairOptions) (ES256KeyPair, error) {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GenerateES256KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Generating ES256 key pair...")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate ES256 private key", "error", err)
		return ES256KeyPair{}, err
	}

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to encode ES256 private key", "error", err)
		return ES256KeyPair{}, err
	}

	publicKeyValue, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse ES256 public key", "error", err)
		return ES256KeyPair{}, err
	}

	kid := utils.ExtractKeyID(publicKeyValue)
	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	if _, err := v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   kid,
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, opts.AccountID),
		SecretValue: privKeyBase64,
		Environment: v.env,
	}); err != nil {
		return ES256KeyPair{}, err
	}

	return ES256KeyPair{
		Kid:       kid,
		PublicKey: utils.EncodeP256Jwk(&priv.PublicKey, kid),
	}, nil
}

func (v *Vault) GetES256PrivateKey(ctx context.Context, opts GetPrivateKeyOptions) (*ecdsa.PrivateKey, error) {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "GetES256KeyPair",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting ES256 private key...")

	privateKeyData, err := v.getDecodedPrivateKey(logger, ctx, opts)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyData.(*ecdsa.PrivateKey)
	if !ok {
		logger.ErrorContext(ctx, "Key is not a valid ES256 private key")
		return nil, fmt.Errorf("invalid private key")
	}

	return privateKey, nil
}

type DeletePrivateKeyOptions struct {
	RequestID string
	AccountID int
	KID       string
}

func (v *Vault) DeletePrivateKey(ctx context.Context, opts DeletePrivateKeyOptions) error {
	logger := utils.BuildLogger(v.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  keyManagementLocation,
		Method:    "DeletePrivateKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Deleting private key...")

	if _, err := v.client.Secrets().Delete(infisical.DeleteSecretOptions{
		SecretKey:   opts.KID,
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, opts.KID),
		Environment: v.env,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to delete private key", "error", err)
		return err
	}

	return nil
}
