// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	clientCredentialsLocation string = "client_credentials"

	// The client credentials secret length is set to 32 bytes to ensure a high level of entropy
	// and security
	clientCredentialsSecretBytes int = 32

	clientCredentialsIDLength     = 22 // Client ID length is 22 characters, which is the length of a base62 encoded UUID
	clientCredentialsSecretLength = 65 // Client Secret length is at least 65 characters, which is the length of a base64 encoded secret + secret id
)

type clientCredentialsSecretOptions struct {
	requestID   string
	accountID   int32
	storageMode database.SecretStorageMode
	expiresIn   time.Duration
	usage       database.CredentialsUsage
	dekFN       crypto.GetDEKtoEncrypt
}

func (s *Services) clientCredentialsSecret(
	ctx context.Context,
	qrs *database.Queries,
	opts clientCredentialsSecretOptions,
) (int32, string, string, time.Time, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, clientCredentialsLocation, "clientCredentialsSecret").With(
		"accountId", opts.accountID,
		"usage", opts.usage,
		"storageMode", opts.storageMode,
	)
	logger.InfoContext(ctx, "Generating client credentials secret...")

	secretID := utils.Base64UUID()
	secret, err := utils.GenerateBase64Secret(clientCredentialsSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate secret", "error", err)
		return 0, "", "", time.Time{}, exceptions.NewInternalServerError()
	}

	exp := time.Now().Add(opts.expiresIn)
	if opts.storageMode == database.SecretStorageModeHashed {
		hashedSecret, err := utils.Argon2HashString(secret)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to hash secret", "error", err)
			return 0, "", "", time.Time{}, exceptions.NewInternalServerError()
		}

		id, err := qrs.CreateCredentialsSecret(ctx, database.CreateCredentialsSecretParams{
			AccountID:    opts.accountID,
			SecretID:     secretID,
			ClientSecret: hashedSecret,
			StorageMode:  opts.storageMode,
			DekKid:       pgtype.Text{Valid: false},
			ExpiresAt:    exp,
			Usage:        opts.usage,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create credentials secret", "error", err)
			return 0, "", "", time.Time{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Created credentials secret with hashed storage mode", "secretId", secretID)
		return id, secretID, secret, exp, nil
	}

	dekID, encryptedSecret, serviceErr := s.crypto.EncryptWithDEK(ctx, crypto.EncryptWithDEKOptions{
		RequestID: opts.requestID,
		GetDEKfn:  opts.dekFN,
		PlainText: secret,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to encrypt secret with DEK", "serviceError", serviceErr)
		return 0, "", "", time.Time{}, exceptions.NewInternalServerError()
	}

	id, err := qrs.CreateCredentialsSecret(ctx, database.CreateCredentialsSecretParams{
		AccountID:    opts.accountID,
		SecretID:     secretID,
		ClientSecret: encryptedSecret,
		StorageMode:  opts.storageMode,
		DekKid:       pgtype.Text{String: dekID, Valid: true},
		ExpiresAt:    exp,
		Usage:        opts.usage,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create credentials secret with DEK", "error", err)
		return 0, "", "", time.Time{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Created credentials secret with DEK storage mode",
		"secretId", secretID, "dekId", dekID,
	)
	return id, secretID, secret, exp, nil
}

func mapAlgorithmToTokenCryptoSuite(algorithm string) utils.SupportedCryptoSuite {
	if algorithm == string(utils.SupportedCryptoSuiteEd25519) {
		return utils.SupportedCryptoSuiteEd25519
	}

	return utils.SupportedCryptoSuiteES256
}

type clientCredentialsKeyOptions struct {
	requestID       string
	accountID       int32
	accountPublicID uuid.UUID
	expiresIn       time.Duration
	usage           database.CredentialsUsage
	cryptoSuite     utils.SupportedCryptoSuite
}

func buildES256Jwk(
	ctx context.Context,
	logger *slog.Logger,
) (string, []byte, utils.JWK, *exceptions.ServiceError) {
	logger.InfoContext(ctx, "Generating ES256 JWK...")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return "", nil, nil, exceptions.NewInternalServerError()
	}

	pub := priv.Public().(*ecdsa.PublicKey)
	kid := utils.ExtractECDSAKeyID(pub)
	dbJwk := utils.EncodeP256Jwk(pub, kid)

	jsonJwk, err := json.Marshal(dbJwk)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal jwk", "error", err)
		return "", nil, nil, exceptions.NewInternalServerError()
	}

	privateJWK := utils.EncodeP256JwkPrivate(priv, kid)
	logger.InfoContext(ctx, "Generated ES256 JWK successfully", "kid", kid)
	return kid, jsonJwk, &privateJWK, nil
}

func buildEdDSAJwk(
	ctx context.Context,
	logger *slog.Logger,
) (string, []byte, utils.JWK, *exceptions.ServiceError) {
	logger.InfoContext(ctx, "Generating EdDSA JWK...")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return "", nil, nil, exceptions.NewInternalServerError()
	}

	kid := utils.ExtractEd25519KeyID(pub)
	dbJwk := utils.EncodeEd25519Jwk(pub, kid)
	jsonJwk, err := json.Marshal(dbJwk)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal jwk", "error", err)
		return "", nil, nil, exceptions.NewInternalServerError()
	}

	privateJWK := utils.EncodeEd25519JwkPrivate(priv, pub, kid)
	logger.InfoContext(ctx, "Generated EdDSA JWK successfully", "kid", kid)
	return kid, jsonJwk, &privateJWK, nil
}

type buildClientCredentialsJwkOptions struct {
	requestID   string
	cryptoSuite utils.SupportedCryptoSuite
}

func (s *Services) buildClientCredentialsJwk(
	ctx context.Context,
	opts buildClientCredentialsJwkOptions,
) (string, []byte, utils.JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, oauthLocation, "BuildClientCredentialsJwk")
	logger.InfoContext(ctx, "Building client credentials JWK...")

	switch opts.cryptoSuite {
	case utils.SupportedCryptoSuiteES256:
		return buildES256Jwk(ctx, logger)
	case utils.SupportedCryptoSuiteEd25519:
		return buildEdDSAJwk(ctx, logger)
	default:
		logger.ErrorContext(ctx, "Unsupported crypto suite", "cryptoSuite", opts.cryptoSuite)
		return "", nil, nil, exceptions.NewInternalServerError()
	}
}

func (s *Services) clientCredentialsKey(
	ctx context.Context,
	opts clientCredentialsKeyOptions,
) (database.CreateCredentialsKeyParams, utils.JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, clientCredentialsLocation, "clientCredentialsKey").With(
		"AccountID", opts.accountID,
	)
	logger.InfoContext(ctx, "Generating client credentials key...")

	cryptoSuite, err := mapCryptoSuite(opts.cryptoSuite)
	if err != nil {
		logger.ErrorContext(ctx, "Invalid crypto suite", "error", err)
		return database.CreateCredentialsKeyParams{}, nil, exceptions.NewInternalServerError()
	}

	kid, jsonJwk, privJwk, serviceErr := s.buildClientCredentialsJwk(ctx, buildClientCredentialsJwkOptions{
		requestID:   opts.requestID,
		cryptoSuite: opts.cryptoSuite,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate client credentials key", "serviceError", serviceErr)
		return database.CreateCredentialsKeyParams{}, nil, serviceErr
	}

	return database.CreateCredentialsKeyParams{
		AccountID:   opts.accountID,
		PublicKid:   kid,
		PublicKey:   jsonJwk,
		ExpiresAt:   time.Now().Add(opts.expiresIn),
		Usage:       opts.usage,
		CryptoSuite: cryptoSuite,
	}, privJwk, nil
}

func isMoreThanHalfExpiry(createdAt, expiresAt time.Time) bool {
	now := time.Now()
	if now.Before(createdAt) || now.After(expiresAt) {
		return false
	}

	totalDuration := expiresAt.Sub(createdAt)
	halfDuration := totalDuration / 2
	elapsedDuration := now.Sub(createdAt)
	return elapsedDuration >= halfDuration
}

type BuildGetClientCredentialsKeyFnOptions struct {
	RequestID string
	Usage     database.CredentialsUsage
}

func (s *Services) BuildGetClientCredentialsKeyPublicJWKFn(
	ctx context.Context,
	opts BuildGetClientCredentialsKeyFnOptions,
) tokens.GetPublicJWK {
	logger := s.buildLogger(opts.RequestID, clientCredentialsLocation, "BuildGetClientCredentialsKey").With(
		"Usage", opts.Usage,
	)
	logger.InfoContext(ctx, "Building get client credentials key function...")

	return func(kid string, cryptoSuite utils.SupportedCryptoSuite) (utils.JWK, error) {
		logger.InfoContext(ctx, "Getting client credentials key by public KID...")

		dbCryptoSuite, err := mapCryptoSuite(cryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Invalid crypto suite", "error", err)
			return nil, err
		}

		publicJWK, err := s.database.FindCredentialsKeyPublicKeyByPublicKIDCryptoSuiteAndUsage(
			ctx,
			database.FindCredentialsKeyPublicKeyByPublicKIDCryptoSuiteAndUsageParams{
				PublicKid:   kid,
				Usage:       opts.Usage,
				CryptoSuite: dbCryptoSuite,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find client credentials key", "error", err)
			return nil, err
		}

		logger.InfoContext(ctx, "Successfully fetched client credentials key")
		return utils.JsonToJWK(publicJWK)
	}
}

func (s *Services) BuildGetAccountClientCredentialsSecretFn(
	ctx context.Context,
	requestID string,
) tokens.GetDecryptedSecret {
	logger := s.buildLogger(requestID, clientCredentialsLocation, "BuildGetAccountClientCredentialsSecretFn")
	logger.InfoContext(ctx, "Building get client credentials secret function...")

	return func(secretID string) ([]byte, error) {
		logger.InfoContext(ctx, "Getting client credentials secret by ID...")

		secret, err := s.database.FindValidCredentialsSecretBySecretID(ctx, secretID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find client credentials secret", "error", err)
			return nil, err
		}
		if secret.StorageMode != database.SecretStorageModeEncrypted {
			logger.WarnContext(ctx, "Client credentials secret is not encrypted", "storageMode", secret.StorageMode)
			return nil, errors.New("client credentials secret is not encrypted")
		}

		decryptedSecret, serviceErr := s.crypto.DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
			RequestID: requestID,
			GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
				RequestID: requestID,
				AccountID: secret.AccountID,
			}),
			GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: requestID,
				AccountID: secret.AccountID,
			}),
			StoreReEncryptedDataFn: func(
				_ crypto.EntityID,
				dekID crypto.DEKID,
				ciphertext crypto.DEKCiphertext,
			) *exceptions.ServiceError {
				if err := s.database.UpdateCredentialsSecretClientSecret(
					ctx,
					database.UpdateCredentialsSecretClientSecretParams{
						ID:           secret.ID,
						ClientSecret: ciphertext,
						DekKid:       pgtype.Text{Valid: true, String: dekID},
					},
				); err != nil {
					logger.ErrorContext(ctx, "Failed to update client credentials secret with re-encrypted DEK",
						"error", err,
					)
					return exceptions.FromDBError(err)
				}

				logger.InfoContext(ctx, "Successfully updated client credentials secret with re-encrypted DEK")
				return nil
			},
			EntityID:   secretID,
			Ciphertext: secret.ClientSecret,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to decrypt client credentials secret", "serviceError", serviceErr)
			return nil, serviceErr
		}

		logger.InfoContext(ctx, "Successfully fetched client credentials secret")
		return []byte(fmt.Sprintf("%s.%s", secretID, decryptedSecret)), nil
	}
}

type ProcessClientCredentialsLoginDataOptions struct {
	RequestID    string
	ClientID     string
	ClientSecret string
	AuthHeader   string
}

func (s *Services) ProcessClientCredentialsLoginData(
	ctx context.Context,
	opts ProcessClientCredentialsLoginDataOptions,
) (string, string, database.AuthMethod, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthLocation, "ProcessClientCredentialsLoginData")
	logger.InfoContext(ctx, "Processing client credentials login data...")

	if opts.AuthHeader == "" {
		logger.InfoContext(ctx, "Auth header is empty")
		if opts.ClientID == "" || opts.ClientSecret == "" {
			logger.WarnContext(ctx, "Client ID and/or Client Secret is empty",
				"clientIdLength", len(opts.ClientID),
				"clientSecretLength", len(opts.ClientSecret),
			)
			return "", "", "", exceptions.NewValidationError("Client ID and/or Client Secret is empty")
		}

		clientID := strings.TrimSpace(opts.ClientID)
		clientIDLen := len(clientID)
		if clientIDLen != clientCredentialsIDLength {
			logger.WarnContext(ctx, "Client ID must be 22 characters long", "clientIdLength", clientIDLen)
			return "", "", "", exceptions.NewUnauthorizedError()
		}

		clientSecret := strings.TrimSpace(opts.ClientSecret)
		clientSecretLen := len(clientSecret)
		if clientSecretLen < clientCredentialsSecretLength {
			logger.WarnContext(ctx, "Client Secret must be at least 65 characters long",
				"clientSecretLength", clientSecretLen,
			)
			return "", "", "", exceptions.NewUnauthorizedError()
		}

		logger.InfoContext(ctx, "Returning client ID and secret from options",
			"clientID", clientID,
			"authMethod", database.AuthMethodClientSecretPost,
		)
		return clientID, clientSecret, database.AuthMethodClientSecretPost, nil
	}

	logger.InfoContext(ctx, "Auth header is not empty, processing auth header...")
	authParts := strings.Split(strings.TrimSpace(opts.AuthHeader), " ")
	if len(authParts) != 2 || utils.Lowered(authParts[0]) != "basic" {
		logger.WarnContext(ctx, "Auth header is not valid basic auth")
		return "", "", "", exceptions.NewUnauthorizedError()
	}

	decoded, err := base64.StdEncoding.DecodeString(authParts[1])
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decode base64 encoded auth header", "error", err)
		return "", "", "", exceptions.NewUnauthorizedError()
	}

	decodedSlice := strings.Split(string(decoded), ":")
	if len(decodedSlice) != 2 {
		return "", "", "", exceptions.NewUnauthorizedError()
	}

	clientID := decodedSlice[0]
	logger.InfoContext(ctx, "Successfully processed client credentials login data from auth header",
		"clientID", clientID,
		"authMethod", database.AuthMethodClientSecretBasic,
	)
	return clientID, decodedSlice[1], database.AuthMethodClientSecretBasic, nil
}
