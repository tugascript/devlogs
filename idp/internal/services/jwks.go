// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	jwkLocation = "jwks"
)

func isDistributedJWK(name database.TokenKeyType) bool {
	return name == database.TokenKeyTypeAccess || name == database.TokenKeyTypeClientCredentials || name == database.TokenKeyTypeIDToken
}

func mapCryptoSuite(cryptoSuite utils.SupportedCryptoSuite) (database.TokenCryptoSuite, error) {
	switch cryptoSuite {
	case utils.SupportedCryptoSuiteEd25519:
		return database.TokenCryptoSuiteEdDSA, nil
	case utils.SupportedCryptoSuiteES256:
		return database.TokenCryptoSuiteES256, nil
	default:
		return "", fmt.Errorf("unsupported crypto suite: %s", cryptoSuite)
	}
}

func mapDBCryptoSuite(cryptoSuite database.TokenCryptoSuite) (utils.SupportedCryptoSuite, error) {
	switch cryptoSuite {
	case database.TokenCryptoSuiteEdDSA:
		return utils.SupportedCryptoSuiteEd25519, nil
	case database.TokenCryptoSuiteES256:
		return utils.SupportedCryptoSuiteES256, nil
	default:
		return "", fmt.Errorf("unsupported crypto suite: %s", cryptoSuite)
	}
}

type createAndCacheJWKOptions struct {
	requestID   string
	keyType     database.TokenKeyType
	storeFN     crypto.StorePrivateKey
	getDEKfn    crypto.GetDEKtoEncrypt
	cryptoSuite utils.SupportedCryptoSuite
}

func (s *Services) createAndCacheJWK(
	ctx context.Context,
	opts createAndCacheJWKOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, jwkLocation, "createAndCacheGlobalJWK")
	logger.InfoContext(ctx, "Creating and caching global JWK...")

	encOpts := crypto.GenerateKeyPairOptions{
		RequestID: opts.requestID,
		GetDEKfn:  opts.getDEKfn,
		StoreFN:   opts.storeFN,
	}
	if opts.cryptoSuite == utils.SupportedCryptoSuiteES256 {
		if _, err := s.crypto.GenerateES256KeyPair(ctx, encOpts); err != nil {
			logger.ErrorContext(ctx, "Failed to generate ES256 key pair", "error", err)
			return exceptions.NewServerError()
		}

		return nil
	}

	if _, err := s.crypto.GenerateEd25519KeyPair(ctx, encOpts); err != nil {
		logger.ErrorContext(ctx, "Failed to generate Ed25519 key pair", "error", err)
		return exceptions.NewServerError()
	}

	return nil
}

type buildEncryptedJWKFnOptions struct {
	requestID string
	keyType   database.TokenKeyType
	ttl       int64
}

func (s *Services) buildEncryptedJWKFn(
	ctx context.Context,
	logger *slog.Logger,
	opts buildEncryptedJWKFnOptions,
) crypto.GetEncryptedJWK {
	return func(
		cryptoSuite utils.SupportedCryptoSuite,
	) (crypto.JWKkid, crypto.EncryptedJWKPrivKey, crypto.DEKID,
		crypto.EncryptedDEK, crypto.KEKID, *exceptions.ServiceError) {
		jwkKID, encPrivKey, dekID, found, err := s.cache.GetJWKPrivateKey(ctx, cache.GetJWKPrivateKeyOptions{
			RequestID:   opts.requestID,
			Suffix:      "global",
			CryptoSuite: cryptoSuite,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK private key from cache", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		getDecDEK := s.buildGetGlobalDecDEKFn(ctx, logger, opts.requestID)
		if found {
			logger.InfoContext(ctx, "JWK private key found in cache", "kid", jwkKID)

			dek, kekKID, serviceErr := getDecDEK(dekID)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to get DEK for decryption", "serviceError", serviceErr)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "DEK not found in cache, getting from database", "dekKID", dekID)
			return jwkKID, encPrivKey, dekID, dek, kekKID, nil
		}

		jwkEnt, err := s.database.GetGlobalTokenSigningKey(ctx, database.GetGlobalTokenSigningKeyParams{
			KeyType:   opts.keyType,
			ExpiresAt: time.Now().Add(-1 * (time.Hour + time.Duration(opts.ttl)*time.Second)),
		})
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get global token signing key", "error", err)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "JWK not found creating and caching global JWK...")
			if serviceErr := s.createAndCacheJWK(ctx, createAndCacheJWKOptions{
				requestID:   opts.requestID,
				keyType:     opts.keyType,
				cryptoSuite: cryptoSuite,
				getDEKfn:    s.buildGetEncGlobalDEK(ctx, logger, opts.requestID),
				storeFN: func(dekKid string, cryptoSuite utils.SupportedCryptoSuite, kid, encryptedKey string, pubKey utils.JWK) (int32, *exceptions.ServiceError) {
					dbCryptoSuite, err := mapCryptoSuite(cryptoSuite)
					if err != nil {
						logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
						return 0, exceptions.NewServerError()
					}

					pubKeyBytes, err := pubKey.MarshalJSON()
					if err != nil {
						logger.ErrorContext(ctx, "Failed to encode public key to JSON", "error", err)
						return 0, exceptions.NewServerError()
					}

					id, err := s.database.CreateTokenSigningKey(ctx, database.CreateTokenSigningKeyParams{
						Kid:           kid,
						KeyType:       opts.keyType,
						PublicKey:     pubKeyBytes,
						PrivateKey:    encryptedKey,
						DekKid:        dekKid,
						CryptoSuite:   dbCryptoSuite,
						Usage:         database.TokenKeyUsageGlobal,
						ExpiresAt:     time.Now().Add(time.Duration(s.jwkExpDays) * time.Hour * 24),
						IsDistributed: isDistributedJWK(opts.keyType),
					})
					if err != nil {
						logger.ErrorContext(ctx, "Failed to create token signing key", "error", err)
						return 0, exceptions.FromDBError(err)
					}

					if err := s.cache.SaveJWK(ctx, cache.SaveJWKOptions{
						RequestID:   opts.requestID,
						Prefix:      "global",
						CryptoSuite: cryptoSuite,
						KeyID:       kid,
						PublicKey:   pubKeyBytes,
					}); err != nil {
						logger.ErrorContext(ctx, "Failed to save JWK to cache", "error", err)
						return 0, exceptions.NewServerError()
					}
					if err := s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
						RequestID:   opts.requestID,
						Suffix:      "global",
						CryptoSuite: cryptoSuite,
						KID:         kid,
						EncPrivKey:  encryptedKey,
					}); err != nil {
						logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
						return 0, exceptions.NewServerError()
					}

					jwkKID = kid
					encPrivKey = encryptedKey
					dekID = dekKid
					return id, nil
				},
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create JWK", "serviceError", serviceErr)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			dek, kekKID, serviceErr := getDecDEK(dekID)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to get DEK for decryption", "serviceError", serviceErr)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "DEK not found in cache, getting from database", "dekKID", dekID)
			return jwkKID, encPrivKey, dekID, dek, kekKID, nil
		}

		dbCryptoSuite, err := mapDBCryptoSuite(jwkEnt.CryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		if dbCryptoSuite != cryptoSuite {
			logger.WarnContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		dek, kekKID, serviceErr := getDecDEK(dekID)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "serviceError", serviceErr)
			return "", "", "", "", uuid.Nil, serviceErr
		}

		if err := s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
			RequestID:   opts.requestID,
			Suffix:      "global",
			CryptoSuite: cryptoSuite,
			KID:         jwkKID,
			EncPrivKey:  jwkEnt.PrivateKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "JWK cached successfully", "kid", jwkEnt.Kid, "crypto_suite", dbCryptoSuite)
		return jwkEnt.Kid, jwkEnt.PrivateKey, dekID, dek, kekKID, nil
	}
}

func (s *Services) buildGetVerifyKeyFn(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	keyType database.TokenKeyType,
) tokens.GetPublicJWK {
	return func(kid string, cryptoSuite utils.SupportedCryptoSuite) (utils.JWK, error) {
		jwk, found, err := s.cache.GetJWK(ctx, cache.GetJWKOptions{
			RequestID:   requestID,
			Prefix:      "global",
			CryptoSuite: cryptoSuite,
			KeyID:       kid,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from cache", "error", err)
			return nil, err
		}
		if found {
			logger.InfoContext(ctx, "JWK found in cache", "kid", kid)
			return jwk, nil
		}

		dbCryptoSuite, err := mapCryptoSuite(cryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return nil, exceptions.NewServerError()
		}

		jwkEnt, err := s.database.FindTokenSigningKeyByKID(ctx, kid)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from database", "error", err)
			return nil, err
		}
		if jwkEnt.Usage != database.TokenKeyUsageGlobal {
			logger.ErrorContext(ctx, "JWK is not a global JWK", "kid", kid)
			return nil, exceptions.NewUnauthorizedError()
		}
		if jwkEnt.KeyType != keyType {
			logger.ErrorContext(ctx, "JWK is not the expected key type", "kid", kid, "expectedKeyType", keyType, "actualKeyType", jwkEnt.KeyType)
			return nil, exceptions.NewUnauthorizedError()
		}
		if dbCryptoSuite != jwkEnt.CryptoSuite {
			logger.InfoContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return nil, exceptions.NewUnauthorizedError()
		}

		jwk, err = utils.JsonToJWK(jwkEnt.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert JWK to JSON", "error", err)
			return nil, err
		}
		if err := s.cache.SaveJWK(ctx, cache.SaveJWKOptions{
			RequestID:   requestID,
			Prefix:      "global",
			CryptoSuite: cryptoSuite,
			KeyID:       jwkEnt.Kid,
			PublicKey:   jwkEnt.PublicKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK to cache", "error", err)
			return nil, err
		}

		return jwk, nil
	}
}

func (s *Services) GetAndCacheGlobalDistributedJWK(
	ctx context.Context,
	requestID string,
) (string, []utils.JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, jwkLocation, "GetAndCacheGlobalDistributedJWK")
	logger.InfoContext(ctx, "Getting and caching global distributed JWKs...")

	etag, jwks, found, err := s.cache.GetPublicJWKs(ctx, cache.GetPublicJWKsOptions{
		RequestID: requestID,
		Prefix:    "global",
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get public JWKs from cache", "error", err)
		return "", nil, exceptions.NewServerError()
	}
	if found {
		logger.InfoContext(ctx, "Public JWKs found in cache", "etag", etag)
		return etag, jwks, nil
	}

	publicJwks, err := s.database.FindGlobalDistributedTokenSigningKeyPublicKeys(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get global distributed token signing keys from database", "error", err)
		return "", nil, exceptions.FromDBError(err)
	}

	etag, err = s.cache.SavePublicJWKs(ctx, cache.SavePublicJWKsOptions{
		RequestID: requestID,
		Prefix:    "global",
		JWKs:      publicJwks,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save public JWKs to cache", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	jwks, err = utils.MapSliceWithErr(publicJwks, func(jwkBytes *[]byte) (utils.JWK, error) {
		return utils.JsonToJWK(*jwkBytes)
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to convert JWK bytes to JWK", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Global distributed JWKs cached successfully", "etag", etag, "count", len(jwks))
	return etag, jwks, nil
}

type buildEncryptedAccountJWKFnOptions struct {
	requestID string
	keyType   database.TokenKeyType
	accountID int32
}

func (s *Services) buildEncryptedAccountJWKFn(
	ctx context.Context,
	logger *slog.Logger,
	opts buildEncryptedAccountJWKFnOptions,
) crypto.GetEncryptedJWK {
	return func(
		cryptoSuite utils.SupportedCryptoSuite,
	) (crypto.JWKkid, crypto.EncryptedJWKPrivKey, crypto.DEKID,
		crypto.EncryptedDEK, crypto.KEKID, *exceptions.ServiceError) {
		suffix := fmt.Sprintf("account:%d", opts.accountID)
		kid, encPrivKey, dekID, found, err := s.cache.GetJWKPrivateKey(ctx, cache.GetJWKPrivateKeyOptions{
			RequestID:   opts.requestID,
			Suffix:      suffix,
			CryptoSuite: cryptoSuite,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from cache", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		getDEKfn := s.buildGetDecAccountDEKFn(ctx, logger, buildGetDecAccountDEKFnOptions{
			requestID: opts.requestID,
			accountID: opts.accountID,
		})
		if found {
			logger.InfoContext(ctx, "JWK private key found in cache", "kid", kid)

			dek, kekKID, serviceErr := getDEKfn(dekID)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to get DEK for decryption", "serviceError", serviceErr)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			logger.InfoContext(ctx, "DEK not found in cache, getting from database", "dekKID", dekID)
			return kid, encPrivKey, dekID, dek, kekKID, nil
		}

		jwkEnt, err := s.database.FindAccountTokenSigningKeyByAccountID(
			ctx,
			database.FindAccountTokenSigningKeyByAccountIDParams{
				AccountID: opts.accountID,
				KeyType:   opts.keyType,
			},
		)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get JWK from database", "error", err)
				return "", "", "", "", uuid.Nil, serviceErr
			}

			if serviceErr := s.createAndCacheJWK(ctx, createAndCacheJWKOptions{
				requestID: opts.requestID,
				keyType:   opts.keyType,
				storeFN: func(
					dekKid string,
					cryptoSuite utils.SupportedCryptoSuite,
					kid, encryptedKey string,
					pubKey utils.JWK,
				) (int32, *exceptions.ServiceError) {
					dbCryptoSuite, err := mapCryptoSuite(cryptoSuite)
					if err != nil {
						logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
						return 0, exceptions.NewServerError()
					}

					pubKeyBytes, err := pubKey.MarshalJSON()
					if err != nil {
						logger.ErrorContext(ctx, "Failed to encode public key to JSON", "error", err)
						return 0, exceptions.NewServerError()
					}

					var serviceErr *exceptions.ServiceError
					qrs, txn, err := s.database.BeginTx(ctx)
					if err != nil {
						logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
						return 0, exceptions.FromDBError(err)
					}
					defer func() {
						logger.DebugContext(ctx, "Finalizing transaction")
						s.database.FinalizeTx(ctx, txn, err, serviceErr)
					}()

					id, err := qrs.CreateTokenSigningKey(ctx, database.CreateTokenSigningKeyParams{
						Kid:           kid,
						KeyType:       opts.keyType,
						PublicKey:     pubKeyBytes,
						PrivateKey:    encryptedKey,
						DekKid:        dekKid,
						CryptoSuite:   dbCryptoSuite,
						ExpiresAt:     time.Now().Add(time.Duration(s.jwkExpDays) * time.Hour * 24),
						Usage:         database.TokenKeyUsageAccount,
						IsDistributed: isDistributedJWK(opts.keyType),
					})
					if err != nil {
						logger.ErrorContext(ctx, "Failed to create token signing key", "error", err)
						serviceErr = exceptions.FromDBError(err)
						return 0, serviceErr
					}

					if err = qrs.CreateAccountTokenSigningKey(ctx, database.CreateAccountTokenSigningKeyParams{
						AccountID:         opts.accountID,
						TokenSigningKeyID: id,
					}); err != nil {
						logger.ErrorContext(ctx, "Failed to create account token signing key", "error", err)
						serviceErr = exceptions.FromDBError(err)
						return 0, serviceErr
					}
					if err = s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
						RequestID:   opts.requestID,
						Suffix:      suffix,
						CryptoSuite: cryptoSuite,
						DEKID:       dekKid,
						KID:         kid,
						EncPrivKey:  encryptedKey,
					}); err != nil {
						logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
						serviceErr = exceptions.NewServerError()
						return 0, serviceErr
					}

					logger.InfoContext(ctx, "JWK cached successfully", "kid", kid, "crypto_suite", dbCryptoSuite)
					return id, nil
				},
				getDEKfn: s.buildGetEncAccountDEK(
					ctx,
					logger,
					getEncAccountDEKOptions{
						requestID: opts.requestID,
						accountID: opts.accountID,
					},
				),
				cryptoSuite: cryptoSuite,
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create and cache JWK", "serviceError", serviceErr)
				return "", "", "", "", uuid.Nil, serviceErr
			}
		}

		dbCryptoSuite, err := mapDBCryptoSuite(jwkEnt.CryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		if dbCryptoSuite != cryptoSuite {
			logger.WarnContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		dek, kekKID, serviceErr := getDEKfn(dekID)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to get DEK for decryption", "serviceError", serviceErr)
			return "", "", "", "", uuid.Nil, serviceErr
		}

		if err := s.cache.SaveJWK(ctx, cache.SaveJWKOptions{
			RequestID:   opts.requestID,
			Prefix:      suffix,
			CryptoSuite: cryptoSuite,
			KeyID:       jwkEnt.Kid,
			PublicKey:   jwkEnt.PublicKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK to cache", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}
		if err := s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
			RequestID:   opts.requestID,
			Suffix:      suffix,
			CryptoSuite: cryptoSuite,
			KID:         jwkEnt.Kid,
			EncPrivKey:  jwkEnt.PrivateKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
			return "", "", "", "", uuid.Nil, exceptions.NewServerError()
		}

		return jwkEnt.Kid, jwkEnt.PrivateKey, dekID, dek, kekKID, nil
	}
}

type buildVerifyAccountKeyFnOptions struct {
	requestID string
	accountID int32
	keyType   database.TokenKeyType
}

func (s *Services) buildVerifyAccountKeyFn(
	ctx context.Context,
	logger *slog.Logger,
	opts buildVerifyAccountKeyFnOptions,
) tokens.GetPublicJWK {
	return func(kid string, cryptoSuite utils.SupportedCryptoSuite) (utils.JWK, error) {
		suffix := fmt.Sprintf("account:%d", opts.accountID)
		jwk, found, err := s.cache.GetJWK(ctx, cache.GetJWKOptions{
			RequestID:   opts.requestID,
			Prefix:      suffix,
			CryptoSuite: cryptoSuite,
			KeyID:       kid,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from cache", "error", err)
			return nil, err
		}
		if found {
			logger.InfoContext(ctx, "JWK found in cache", "kid", kid)
			return jwk, nil
		}

		dbCryptoSuite, err := mapCryptoSuite(cryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return nil, exceptions.NewServerError()
		}

		jwkEnt, err := s.database.FindAccountTokenSigningKeyByAccountIDAndKID(
			ctx,
			database.FindAccountTokenSigningKeyByAccountIDAndKIDParams{
				AccountID: opts.accountID,
				Kid:       kid,
			},
		)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from database", "error", err)
			return nil, err
		}
		if jwkEnt.Usage != database.TokenKeyUsageAccount {
			logger.ErrorContext(ctx, "JWK is not an account JWK", "kid", kid)
			return nil, exceptions.NewUnauthorizedError()
		}
		if jwkEnt.KeyType != opts.keyType {
			logger.ErrorContext(ctx, "JWK is not the expected key type", "kid", kid, "expectedKeyType", opts.keyType, "actualKeyType", jwkEnt.KeyType)
			return nil, exceptions.NewUnauthorizedError()
		}
		if dbCryptoSuite != jwkEnt.CryptoSuite {
			logger.InfoContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return nil, exceptions.NewUnauthorizedError()
		}

		jwk, err = utils.JsonToJWK(jwkEnt.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert JWK to JSON", "error", err)
			return nil, err
		}
		if err := s.cache.SaveJWK(ctx, cache.SaveJWKOptions{
			RequestID:   opts.requestID,
			Prefix:      suffix,
			CryptoSuite: cryptoSuite,
			KeyID:       jwkEnt.Kid,
			PublicKey:   jwkEnt.PublicKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK to cache", "error", err)
			return nil, err
		}

		return jwk, nil
	}
}

type GetAndCacheAccountDistributedJWKOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetAndCacheAccountDistributedJWK(
	ctx context.Context,
	opts GetAndCacheAccountDistributedJWKOptions,
) (string, []utils.JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, jwkLocation, "GetAndCacheAccountDistributedJWK")
	logger.InfoContext(ctx, "Getting and caching account distributed JWKs...", "accountID", opts.AccountID)

	suffix := fmt.Sprintf("account:%d", opts.AccountID)
	etag, jwks, found, err := s.cache.GetPublicJWKs(ctx, cache.GetPublicJWKsOptions{
		RequestID: opts.RequestID,
		Prefix:    suffix,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get public JWKs from cache", "error", err)
		return "", nil, exceptions.NewServerError()
	}
	if found {
		logger.InfoContext(ctx, "Public JWKs found in cache", "etag", etag)
		return etag, jwks, nil
	}

	publicJwks, err := s.database.FindAccountDistributedTokenSigningKeyPublicKeysByAccountID(ctx, opts.AccountID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account distributed token signing keys from database", "error", err)
		return "", nil, exceptions.FromDBError(err)
	}

	etag, err = s.cache.SavePublicJWKs(ctx, cache.SavePublicJWKsOptions{
		RequestID: opts.RequestID,
		Prefix:    suffix,
		JWKs:      publicJwks,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save public JWKs to cache", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	jwks, err = utils.MapSliceWithErr(publicJwks, func(jwkBytes *[]byte) (utils.JWK, error) {
		return utils.JsonToJWK(*jwkBytes)
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to convert JWK bytes to JWK", "error", err)
		return "", nil, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Account distributed JWKs cached successfully", "etag", etag, "count", len(jwks))
	return etag, jwks, nil
}
