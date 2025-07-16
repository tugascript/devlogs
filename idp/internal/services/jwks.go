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

func mapJWKCacheType(keyType database.TokenKeyType) crypto.JWKCacheType {
	switch keyType {
	case database.TokenKeyTypeAccess, database.TokenKeyTypeRefresh, database.TokenKeyTypeClientCredentials:
		return crypto.JWKCacheTypeAuth
	default:
		return crypto.JWKCacheTypePurpose
	}
}

type createJWKOptions struct {
	requestID   string
	keyType     database.TokenKeyType
	storeFN     crypto.StorePrivateKey
	getDEKfn    crypto.GetDEKtoEncrypt
	cryptoSuite utils.SupportedCryptoSuite
}

func (s *Services) createJWK(
	ctx context.Context,
	opts createJWKOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, jwkLocation, "createJWK")
	logger.InfoContext(ctx, "Creating and caching global JWK...")

	encOpts := crypto.GenerateKeyPairOptions{
		RequestID: opts.requestID,
		GetDEKfn:  opts.getDEKfn,
		StoreFN:   opts.storeFN,
		CacheType: mapJWKCacheType(opts.keyType),
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

type buildStoreGlobalJWKfnOptions struct {
	requestID string
	keyType   database.TokenKeyType
	data      map[string]string
}

func (s *Services) buildStoreGlobalJWKfn(
	ctx context.Context,
	opts buildStoreGlobalJWKfnOptions,
) crypto.StorePrivateKey {
	logger := s.buildLogger(opts.requestID, jwkLocation, "buildStoreGlobalJWKfn")
	logger.InfoContext(ctx, "Building store global JWK function...")
	return func(dekKid string, cryptoSuite utils.SupportedCryptoSuite, kid, encryptedKey string, pubKey utils.JWK) (int32, *exceptions.ServiceError) {
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

		logger.InfoContext(ctx, "Storing global JWK", "kid", kid, "cryptoSuite", dbCryptoSuite)
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

		logger.InfoContext(ctx, "JWK saved and cached successfully", "kid", kid, "cryptoSuite", dbCryptoSuite)
		opts.data["kid"] = kid
		opts.data["encryptedKey"] = encryptedKey
		return id, nil
	}
}

type BuildEncryptedJWKFnOptions struct {
	RequestID string
	KeyType   database.TokenKeyType
	TTL       int64
}

func (s *Services) BuildGetGlobalEncryptedJWKFn(
	ctx context.Context,
	opts BuildEncryptedJWKFnOptions,
) crypto.GetEncryptedJWK {
	cacheType := mapJWKCacheType(opts.KeyType)
	logger := s.buildLogger(opts.RequestID, jwkLocation, "BuildGetGlobalEncryptedJWKFn").With(
		"keyType", opts.KeyType, "ttl", opts.TTL, "cacheType", cacheType,
	)
	logger.InfoContext(ctx, "Building encrypted JWK function...")

	return func(
		cryptoSuite utils.SupportedCryptoSuite,
	) (crypto.JWKkid, crypto.DEKCiphertext, crypto.JWKCacheType, *exceptions.ServiceError) {
		logger = logger.With("cryptoSuite", cryptoSuite)
		logger.InfoContext(ctx, "Getting global encrypted JWK from cache...")
		jwkKID, encPrivKey, found, err := s.cache.GetJWKPrivateKey(ctx, cache.GetJWKPrivateKeyOptions{
			RequestID:   opts.RequestID,
			Suffix:      "global",
			CryptoSuite: cryptoSuite,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK private key from cache", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		if found {
			logger.InfoContext(ctx, "JWK found in cache", "jwkKID", jwkKID)
			return jwkKID, encPrivKey, cacheType, nil
		}

		logger.InfoContext(ctx, "JWK not found in cache, checking database...")
		jwkEnt, err := s.database.FindGlobalTokenSigningKey(ctx, database.FindGlobalTokenSigningKeyParams{
			KeyType:   opts.KeyType,
			ExpiresAt: time.Now().Add(-1 * (time.Hour + time.Duration(opts.TTL)*time.Second)),
		})
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get global token signing key", "error", err)
				return "", "", "", serviceErr
			}

			logger.InfoContext(ctx, "JWK not found creating and caching global JWK...")
			data := make(map[string]string)
			if serviceErr := s.createJWK(ctx, createJWKOptions{
				requestID:   opts.RequestID,
				keyType:     opts.KeyType,
				cryptoSuite: cryptoSuite,
				getDEKfn:    s.BuildGetEncGlobalDEKFn(ctx, opts.RequestID),
				storeFN: s.buildStoreGlobalJWKfn(ctx, buildStoreGlobalJWKfnOptions{
					requestID: opts.RequestID,
					keyType:   opts.KeyType,
					data:      data,
				}),
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create JWK", "serviceError", serviceErr)
				return "", "", "", serviceErr
			}

			jwkKID, ok := data["kid"]
			if !ok {
				logger.ErrorContext(ctx, "Failed to get JWK KID from data map")
				return "", "", "", exceptions.NewServerError()
			}

			encPrivKey, ok := data["encryptedKey"]
			if !ok {
				logger.ErrorContext(ctx, "Failed to get encrypted private key from data map")
				return "", "", "", exceptions.NewServerError()
			}

			logger.InfoContext(ctx, "JWK private key cached successfully", "kid", jwkKID)
			return jwkKID, encPrivKey, cacheType, nil
		}

		logger.InfoContext(ctx, "JWK found in database", "kid", jwkEnt.Kid)
		dbCryptoSuite, err := mapDBCryptoSuite(jwkEnt.CryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		if dbCryptoSuite != cryptoSuite {
			logger.WarnContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return "", "", "", exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Saving JWK private key to cache", "kid", jwkEnt.Kid)
		if err := s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
			RequestID:   opts.RequestID,
			Suffix:      "global",
			CryptoSuite: cryptoSuite,
			KID:         jwkEnt.Kid,
			EncPrivKey:  jwkEnt.PrivateKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "JWK cached successfully", "kid", jwkEnt.Kid)
		return jwkEnt.Kid, jwkEnt.PrivateKey, cacheType, nil
	}
}

type BuildGetGlobalVerifyKeyFnOptions struct {
	RequestID string
	KeyType   database.TokenKeyType
}

func (s *Services) BuildGetGlobalPublicKeyFn(
	ctx context.Context,
	opts BuildGetGlobalVerifyKeyFnOptions,
) tokens.GetPublicJWK {
	logger := s.buildLogger(opts.RequestID, jwkLocation, "BuildGetGlobalPublicKeyFn")
	logger.InfoContext(ctx, "Building verify global JWK function...")

	return func(kid string, cryptoSuite utils.SupportedCryptoSuite) (utils.JWK, error) {
		logger = logger.With("kid", kid, "cryptoSuite", cryptoSuite)
		logger.InfoContext(ctx, "Getting global public JWK...")
		jwk, found, err := s.cache.GetJWK(ctx, cache.GetJWKOptions{
			RequestID:   opts.RequestID,
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
		if jwkEnt.KeyType != opts.KeyType {
			logger.ErrorContext(ctx, "JWK is not the expected key type", "kid", kid, "expectedKeyType", opts.KeyType, "actualKeyType", jwkEnt.KeyType)
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
		if err := s.cache.SavePublicJWK(ctx, cache.SavePublicJWKOptions{
			RequestID:   opts.RequestID,
			Prefix:      "global",
			CryptoSuite: cryptoSuite,
			KeyID:       jwkEnt.Kid,
			PublicKey:   jwkEnt.PublicKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK to cache", "error", err)
			return nil, err
		}

		logger.InfoContext(ctx, "JWK cached successfully", "kid", jwkEnt.Kid, "cryptoSuite", dbCryptoSuite)
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

type buildStoreAccountJWKfnOptions struct {
	requestID string
	accountID int32
	keyType   database.TokenKeyType
	data      map[string]string
}

func (s *Services) buildStoreAccountJWKfn(
	ctx context.Context,
	opts buildStoreAccountJWKfnOptions,
) crypto.StorePrivateKey {
	logger := s.buildLogger(opts.requestID, jwkLocation, "buildStoreAccountJWKfn")
	logger.InfoContext(ctx, "Building store account JWK function...")

	return func(
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
			Suffix:      fmt.Sprintf("account:%d", opts.accountID),
			CryptoSuite: cryptoSuite,
			KID:         kid,
			EncPrivKey:  encryptedKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
			serviceErr = exceptions.NewServerError()
			return 0, serviceErr
		}

		logger.InfoContext(ctx, "JWK cached successfully", "kid", kid, "crypto_suite", dbCryptoSuite)
		opts.data["kid"] = kid
		opts.data["encryptedKey"] = encryptedKey
		return id, nil
	}
}

type BuildGetEncryptedAccountJWKFnOptions struct {
	RequestID string
	KeyType   database.TokenKeyType
	AccountID int32
}

func (s *Services) BuildGetEncryptedAccountJWKFn(
	ctx context.Context,
	opts BuildGetEncryptedAccountJWKFnOptions,
) crypto.GetEncryptedJWK {
	cacheType := mapJWKCacheType(opts.KeyType)
	logger := s.buildLogger(opts.RequestID, jwkLocation, "BuildGetEncryptedAccountJWKFn").With(
		"keyType", opts.KeyType, "AccountID", opts.AccountID, "cacheType", cacheType,
	)
	logger.InfoContext(ctx, "Building verify global JWK function...")

	return func(
		cryptoSuite utils.SupportedCryptoSuite,
	) (crypto.JWKkid, crypto.DEKCiphertext, crypto.JWKCacheType, *exceptions.ServiceError) {
		logger = logger.With("cryptoSuite", cryptoSuite)
		logger.InfoContext(ctx, "Getting account encrypted JWK from cache...")

		suffix := fmt.Sprintf("account:%d", opts.AccountID)
		kid, encPrivKey, found, err := s.cache.GetJWKPrivateKey(ctx, cache.GetJWKPrivateKeyOptions{
			RequestID:   opts.RequestID,
			Suffix:      suffix,
			CryptoSuite: cryptoSuite,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from cache", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		if found {
			logger.InfoContext(ctx, "JWK private key found in cache", "kid", kid)
			return kid, encPrivKey, cacheType, nil
		}

		logger.InfoContext(ctx, "JWK private key not found in cache, checking database...")
		jwkEnt, err := s.database.FindAccountTokenSigningKeyByAccountID(
			ctx,
			database.FindAccountTokenSigningKeyByAccountIDParams{
				AccountID: opts.AccountID,
				KeyType:   opts.KeyType,
			},
		)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to get JWK from database", "error", err)
				return "", "", "", serviceErr
			}

			logger.InfoContext(ctx, "JWK not found in database, creating and caching account JWK...")
			data := make(map[string]string)
			if serviceErr := s.createJWK(ctx, createJWKOptions{
				requestID: opts.RequestID,
				keyType:   opts.KeyType,
				storeFN: s.buildStoreAccountJWKfn(ctx, buildStoreAccountJWKfnOptions{
					requestID: opts.RequestID,
					accountID: opts.AccountID,
					keyType:   opts.KeyType,
					data:      data,
				}),
				getDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
					RequestID: opts.RequestID,
					AccountID: opts.AccountID,
				}),
				cryptoSuite: cryptoSuite,
			}); serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to create and cache JWK", "serviceError", serviceErr)
				return "", "", "", serviceErr
			}

			kid, ok := data["kid"]
			if !ok {
				logger.ErrorContext(ctx, "Failed to get JWK KID from data map")
				return "", "", "", exceptions.NewServerError()
			}

			encPrivKey, ok := data["encryptedKey"]
			if !ok {
				logger.ErrorContext(ctx, "Failed to get encrypted private key from data map")
				return "", "", "", exceptions.NewServerError()
			}

			logger.InfoContext(ctx, "JWK private key cached successfully", "kid", kid)
			return kid, encPrivKey, cacheType, nil
		}

		logger.InfoContext(ctx, "JWK private key found in database", "kid", jwkEnt.Kid)
		dbCryptoSuite, err := mapDBCryptoSuite(jwkEnt.CryptoSuite)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to map crypto suite", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		if dbCryptoSuite != cryptoSuite {
			logger.WarnContext(ctx, "Entity crypto suite does not match the token crypto suite",
				"entityCryptoSuite", dbCryptoSuite,
				"cryptoSuite", cryptoSuite,
			)
			return "", "", "", exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Saving JWK private key to cache", "kid", jwkEnt.Kid)
		if err := s.cache.SaveJWKPrivateKey(ctx, cache.SaveJWKPrivateKeyOptions{
			RequestID:   opts.RequestID,
			Suffix:      suffix,
			CryptoSuite: cryptoSuite,
			KID:         jwkEnt.Kid,
			EncPrivKey:  jwkEnt.PrivateKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save JWK private key to cache", "error", err)
			return "", "", "", exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "JWK private key cached successfully", "kid", jwkEnt.Kid)
		return jwkEnt.Kid, jwkEnt.PrivateKey, cacheType, nil
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
		if err := s.cache.SavePublicJWK(ctx, cache.SavePublicJWKOptions{
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
	logger.InfoContext(ctx, "Getting and caching account distributed JWKs...", "AccountID", opts.AccountID)

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

func (s *Services) BuildUpdateJWKDEKFn(
	ctx context.Context,
	requestID string,
) crypto.StoreReEncryptedData {
	logger := s.buildLogger(requestID, jwkLocation, "BuildUpdateJWKDEKFn")
	logger.InfoContext(ctx, "Building update JWK DEK function...")

	return func(kid crypto.EntityID, dekID crypto.DEKID, encPrivKey crypto.DEKCiphertext) *exceptions.ServiceError {
		logger.InfoContext(ctx, "Updating JWK DEK...")
		jwkEnt, err := s.database.FindTokenSigningKeyByKID(ctx, kid)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get JWK from database", "error", err)
			return exceptions.FromDBError(err)
		}

		if err := s.database.UpdateTokenSigningKeyDEKAndPrivateKey(
			ctx,
			database.UpdateTokenSigningKeyDEKAndPrivateKeyParams{
				ID:         jwkEnt.ID,
				DekKid:     dekID,
				PrivateKey: encPrivKey,
			},
		); err != nil {
			logger.ErrorContext(ctx, "Failed to update JWK DEK and private key", "error", err)
			return exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "JWK DEK updated successfully")
		return nil
	}
}
