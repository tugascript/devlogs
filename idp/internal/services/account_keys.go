// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"time"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AppKeyName string

const (
	appKeysLocation string = "app_keys"

	AppKeyNameAccess  AppKeyName = "access"
	AppKeyNameRefresh AppKeyName = "refresh"
	AppKeyNameConfirm AppKeyName = "confirm"
	AppKeyNameClient  AppKeyName = "client"
	AppKeyNameID      AppKeyName = "id"
	AppKeyNameOAuth   AppKeyName = "oauth"
	AppKeyNameReset   AppKeyName = "reset"
	AppKeyName2FA     AppKeyName = "2fa"

	KeyDurationHours int = 4320
)

func isDistributedKey(name AppKeyName) bool {
	return name == AppKeyNameAccess || name == AppKeyNameClient || name == AppKeyNameID || name == AppKeyNameOAuth
}

func getCryptoSuite(isDistributed bool) tokens.SupportedCryptoSuite {
	if isDistributed {
		return tokens.SupportedCryptoSuiteES256
	}
	return tokens.SupportedCryptoSuiteEd25519
}

type generateAccountKeyKeyPairOptions struct {
	requestID   string
	cryptoSuite tokens.SupportedCryptoSuite
	accountDEK  string
	dek         string
}

func (s *Services) generateAccountKeyKeyPair(
	ctx context.Context,
	opts generateAccountKeyKeyPairOptions,
) (encryption.KeyPair, any, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "generateAccountKeyKeyPair").With(
		"cryptoSuite", opts.cryptoSuite,
	)
	logger.InfoContext(ctx, "Generating account key key pair...")

	keyOpts := encryption.GenerateKeyPairOptions{
		RequestID:  opts.requestID,
		AccountDEK: opts.accountDEK,
		StoredDEK:  opts.dek,
	}
	switch opts.cryptoSuite {
	case tokens.SupportedCryptoSuiteES256:
		logger.DebugContext(ctx, "Generating ES256 key pair...")
		keyPair, privateKey, newDek, err := s.encrypt.GenerateES256KeyPair(ctx, keyOpts)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate ES256 key pair", "error", err)
			return encryption.KeyPair{}, nil, "", exceptions.NewServerError()
		}

		return keyPair, privateKey, newDek, nil
	case tokens.SupportedCryptoSuiteEd25519:
		logger.DebugContext(ctx, "Generating Ed25519 key pair...")
		keyPair, privateKey, newDek, err := s.encrypt.GenerateEd25519KeyPair(ctx, keyOpts)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate Ed25519 key pair", "error", err)
			return encryption.KeyPair{}, nil, "", exceptions.NewServerError()
		}

		return keyPair, privateKey, newDek, nil
	default:
		logger.WarnContext(ctx, "Unsupported crypto suite", "cryptoSuite", opts.cryptoSuite)
		return encryption.KeyPair{}, nil, "", exceptions.NewValidationError("unsupported crypto suite")
	}
}

type createAccountKeyOptions struct {
	requestID  string
	accountID  int32
	accountDEK string
	name       AppKeyName
}

func (s *Services) createAccountKey(
	ctx context.Context,
	opts createAccountKeyOptions,
) (dtos.AccountKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createAccountKey").With(
		"accountId", opts.accountID,
		"name", opts.name,
	)
	logger.InfoContext(ctx, "Creating account key...")

	oidcConfig, serviceErr := s.GetOrCreateOIDCConfig(ctx, GetOrCreateOIDCConfigOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create OIDC config", "error", serviceErr)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	isDistributed := isDistributedKey(opts.name)
	cryptoSuite := getCryptoSuite(isDistributed)
	keyPair, privateKey, dek, serviceErr := s.generateAccountKeyKeyPair(ctx, generateAccountKeyKeyPairOptions{
		requestID:   opts.requestID,
		cryptoSuite: cryptoSuite,
		accountDEK:  opts.accountDEK,
		dek:         oidcConfig.DEK(),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate app key key pair", "error", serviceErr)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	publicKeyJSON, err := keyPair.PublicKey.ToJSON()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to convert public key to JSON", "error", err)
		return dtos.AccountKeyDTO{}, exceptions.NewServerError()
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(KeyDurationHours) * time.Hour)
	if dek == "" {
		accountKey, err := s.database.CreateAccountKey(ctx, database.CreateAccountKeyParams{
			OidcConfigID:   oidcConfig.ID(),
			AccountID:      opts.accountID,
			Name:           string(opts.name),
			JwtCryptoSuite: string(cryptoSuite),
			PublicKid:      keyPair.KID,
			PublicKey:      publicKeyJSON,
			PrivateKey:     keyPair.EncryptedPrivateKey(),
			IsDistributed:  isDistributed,
			ExpiresAt:      expiresAt,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			return dtos.AccountKeyDTO{}, exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Account key created successfully")
		return dtos.MapAccountKeyWithKeysToDTO(&accountKey, keyPair.PublicKey, privateKey)
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountKeyDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	accountKey, err := qrs.CreateAccountKey(ctx, database.CreateAccountKeyParams{
		OidcConfigID:   oidcConfig.ID(),
		AccountID:      opts.accountID,
		Name:           string(opts.name),
		JwtCryptoSuite: string(cryptoSuite),
		PublicKid:      keyPair.KID,
		PublicKey:      publicKeyJSON,
		PrivateKey:     keyPair.EncryptedPrivateKey(),
		IsDistributed:  isDistributed,
		ExpiresAt:      expiresAt,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	if err := qrs.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		ID:  opts.accountID,
		Dek: dek,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account key created successfully")
	return dtos.MapAccountKeyWithKeysToDTO(&accountKey, keyPair.PublicKey, privateKey)
}

func (s *Services) decryptAccountKeyPrivateKey(
	ctx context.Context,
	requestID string,
	accountKey *database.AccountKey,
	accountDEK string,
) (interface{}, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, appKeysLocation, "decryptAccountKeyPrivateKey")
	logger.InfoContext(ctx, "Decrypting private key...")

	oidcConfig, serviceErr := s.GetOIDCConfigByAccountID(ctx, GetOIDCConfigByAccountIDOptions{
		RequestID: requestID,
		AccountID: accountKey.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create OIDC config", "error", serviceErr)
		return nil, serviceErr
	}

	opts := encryption.DecryptPrivateKeyOptions{
		RequestID:    requestID,
		EncryptedKey: accountKey.PrivateKey,
		AccountDEK:   accountDEK,
		StoredDEK:    oidcConfig.DEK(),
	}
	var privateKey any
	var newDEK string
	var err error
	switch accountKey.JwtCryptoSuite {
	case string(tokens.SupportedCryptoSuiteES256):
		privateKey, newDEK, err = s.encrypt.DecryptES256PrivateKey(ctx, opts)
	case string(tokens.SupportedCryptoSuiteEd25519):
		privateKey, newDEK, err = s.encrypt.DecryptEd25519PrivateKey(ctx, opts)
	default:
		logger.WarnContext(ctx, "Unsupported crypto suite", "cryptoSuite", accountKey.JwtCryptoSuite)
		return nil, exceptions.NewForbiddenError()
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", err)
		return nil, exceptions.NewServerError()
	}

	if newDEK != "" {
		if err := s.database.UpdateOIDCConfigDek(ctx, database.UpdateOIDCConfigDekParams{
			Dek: newDEK,
			ID:  oidcConfig.ID(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update OIDC config StoredDEK", "error", err)
			return nil, exceptions.FromDBError(err)
		}
	}

	logger.InfoContext(ctx, "Private key decrypted successfully")
	return privateKey, nil
}

type GetOrCreateAccountKeyOptions struct {
	RequestID string
	AccountID int32
	Name      AppKeyName
}

func (s *Services) GetOrCreateAccountKey(
	ctx context.Context,
	opts GetOrCreateAccountKeyOptions,
) (dtos.AccountKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetOrCreateAppKeys").With(
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating app keys...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found")
			return dtos.AccountKeyDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Error getting account", "error", serviceErr)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	expAt := time.Now().Add(-7 * 24 * time.Hour)
	accountKey, err := s.database.FindAccountKeyByAccountIDAndName(ctx, database.FindAccountKeyByAccountIDAndNameParams{
		AccountID: opts.AccountID,
		Name:      string(opts.Name),
		ExpiresAt: expAt,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app key", "error", err)
			return dtos.AccountKeyDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "App key not found, creating new one")
		return s.createAccountKey(ctx, createAccountKeyOptions{
			requestID:  opts.RequestID,
			accountID:  opts.AccountID,
			name:       opts.Name,
			accountDEK: accountDTO.DEK(),
		})
	}

	privateKey, serviceErr := s.decryptAccountKeyPrivateKey(ctx, opts.RequestID, &accountKey, accountDTO.DEK())
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", serviceErr)
		return dtos.AccountKeyDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account key found")
	return dtos.MapAccountKeyToDTO(&accountKey, privateKey)
}

type getMultipleAccountKeysOptions struct {
	requestID     string
	accountID     int32
	names         []AppKeyName
	accountDEK    string
	oidcConfigDEK string
}

func (s *Services) getMultipleAccountKeys(
	ctx context.Context,
	opts getMultipleAccountKeysOptions,
) ([]dtos.AccountKeyDTO, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "getMultipleAccountKeys").With(
		"accountId", opts.accountID,
		"names", opts.names,
	)
	logger.InfoContext(ctx, "Getting multiple account keys...")

	expAt := time.Now().Add(-7 * 24 * time.Hour)
	accountKeys, err := s.database.FindAccountKeyByAccountIDAndNames(ctx, database.FindAccountKeyByAccountIDAndNamesParams{
		AccountID: opts.accountID,
		Names:     utils.MapSlice(opts.names, func(name *AppKeyName) string { return string(*name) }),
		ExpiresAt: expAt,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find account keys", "error", err)
		return nil, "", exceptions.FromDBError(err)
	}

	count := len(accountKeys)
	if count == 0 {
		logger.InfoContext(ctx, "No account keys found")
		return make([]dtos.AccountKeyDTO, 0), "", nil
	}

	var newDEK string
	accountKeyDTOs := make([]dtos.AccountKeyDTO, 0, count)
	for _, accountKey := range accountKeys {
		opts := encryption.DecryptPrivateKeyOptions{
			RequestID:    opts.requestID,
			EncryptedKey: accountKey.PrivateKey,
			AccountDEK:   opts.accountDEK,
			StoredDEK:    opts.oidcConfigDEK,
		}
		var privateKey any
		var err error
		switch accountKey.JwtCryptoSuite {
		case string(tokens.SupportedCryptoSuiteES256):
			privateKey, newDEK, err = s.encrypt.DecryptES256PrivateKey(ctx, opts)
		case string(tokens.SupportedCryptoSuiteEd25519):
			privateKey, newDEK, err = s.encrypt.DecryptEd25519PrivateKey(ctx, opts)
		default:
			logger.WarnContext(ctx, "Unsupported crypto suite", "cryptoSuite", accountKey.JwtCryptoSuite)
			return nil, "", exceptions.NewForbiddenError()
		}
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decrypt private key", "error", err)
			return nil, "", exceptions.NewServerError()
		}

		accountKeyDTO, serviceErr := dtos.MapAccountKeyToDTO(&accountKey, privateKey)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to map account key to DTO", "serviceErr", serviceErr)
			return nil, "", serviceErr
		}

		accountKeyDTOs = append(accountKeyDTOs, accountKeyDTO)
	}

	logger.InfoContext(ctx, "Account keys found successfully...")
	return accountKeyDTOs, newDEK, nil
}

type createMultipleAccountKeysOptions struct {
	requestID     string
	accountID     int32
	accountDEK    string
	oidcConfigID  int32
	oidcConfigDEK string
	names         []AppKeyName
}

func (s *Services) createMultipleAccountKeys(
	ctx context.Context,
	opts createMultipleAccountKeysOptions,
) ([]dtos.AccountKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createMultipleAccountKeys").With(
		"accountId", opts.accountID,
		"names", opts.names,
	)
	logger.InfoContext(ctx, "Creating multiple account keys...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return nil, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	var newDEK string
	accountKeyDTOs := make([]dtos.AccountKeyDTO, 0, len(opts.names))
	now := time.Now()
	expiresAt := now.Add(time.Duration(KeyDurationHours) * time.Hour)
	for _, name := range opts.names {
		isDistributed := isDistributedKey(name)
		cryptoSuite := getCryptoSuite(isDistributed)
		var keyPair encryption.KeyPair
		var privateKey any
		keyPair, privateKey, newDEK, serviceErr = s.generateAccountKeyKeyPair(ctx, generateAccountKeyKeyPairOptions{
			requestID:   opts.requestID,
			accountDEK:  opts.accountDEK,
			dek:         opts.oidcConfigDEK,
			cryptoSuite: cryptoSuite,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate app key key pair", "error", serviceErr)
			return nil, serviceErr
		}

		publicKeyJSON, err := keyPair.PublicKey.ToJSON()
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert public key to JSON", "error", err)
			serviceErr = exceptions.NewServerError()
			return nil, serviceErr
		}

		var accountKey database.AccountKey
		accountKey, err = qrs.CreateAccountKey(ctx, database.CreateAccountKeyParams{
			OidcConfigID:   opts.oidcConfigID,
			AccountID:      opts.accountID,
			Name:           string(name),
			JwtCryptoSuite: string(cryptoSuite),
			PublicKid:      keyPair.KID,
			PublicKey:      publicKeyJSON,
			PrivateKey:     keyPair.EncryptedPrivateKey(),
			IsDistributed:  isDistributed,
			ExpiresAt:      expiresAt,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create account key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return nil, serviceErr
		}

		var accountKeyDTO dtos.AccountKeyDTO
		accountKeyDTO, serviceErr = dtos.MapAccountKeyWithKeysToDTO(&accountKey, keyPair.PublicKey, privateKey)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to map account key to DTO", "serviceErr", serviceErr)
			return nil, serviceErr
		}

		accountKeyDTOs = append(accountKeyDTOs, accountKeyDTO)
	}

	if newDEK != "" {
		if err = s.database.UpdateOIDCConfigDek(ctx, database.UpdateOIDCConfigDekParams{
			ID:  opts.oidcConfigID,
			Dek: newDEK,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update OIDC Config DEK", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return nil, serviceErr
		}
	}

	logger.InfoContext(ctx, "Multiple account keys created successfully", "count", len(accountKeyDTOs))
	return accountKeyDTOs, nil
}

type GetOrCreateMultipleAccountKeysOptions struct {
	RequestID string
	AccountID int32
	Names     []AppKeyName
}

func (s *Services) GetOrCreateMultipleAccountKeys(
	ctx context.Context,
	opts GetOrCreateMultipleAccountKeysOptions,
) ([]dtos.AccountKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetOrCreateMultipleAccountKeys").With(
		"accountId", opts.AccountID,
		"names", opts.Names,
	)
	logger.InfoContext(ctx, "Getting or creating multiple account keys...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "error", serviceErr)
		return nil, serviceErr
	}

	oidcConfigDTO, serviceErr := s.GetOrCreateOIDCConfig(ctx, GetOrCreateOIDCConfigOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get or create OIDC config", "error", serviceErr)
		return nil, serviceErr
	}

	accountKeyDTOs, newDEK, serviceErr := s.getMultipleAccountKeys(ctx, getMultipleAccountKeysOptions{
		requestID:     opts.RequestID,
		accountID:     opts.AccountID,
		names:         opts.Names,
		accountDEK:    accountDTO.DEK(),
		oidcConfigDEK: oidcConfigDTO.DEK(),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account keys", "serviceErr", serviceErr)
		return nil, serviceErr
	}

	namesCount := len(opts.Names)
	keysCount := len(accountKeyDTOs)
	if namesCount == keysCount {
		if newDEK != "" {
			if err := s.database.UpdateOIDCConfigDek(ctx, database.UpdateOIDCConfigDekParams{
				Dek: newDEK,
				ID:  oidcConfigDTO.ID(),
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to update OIDC config DEK", "error", err)
				return nil, exceptions.FromDBError(err)
			}
		}

		logger.InfoContext(ctx, "Got all account keys successfully", "count", keysCount)
		return accountKeyDTOs, nil
	}
	if keysCount == 0 {
		return s.createMultipleAccountKeys(ctx, createMultipleAccountKeysOptions{
			requestID:     opts.RequestID,
			accountID:     opts.AccountID,
			accountDEK:    accountDTO.DEK(),
			oidcConfigID:  oidcConfigDTO.ID(),
			oidcConfigDEK: oidcConfigDTO.DEK(),
			names:         opts.Names,
		})
	}

	existingNames := make(map[string]bool)
	for _, key := range accountKeyDTOs {
		existingNames[key.Name()] = true
	}

	var newNames []AppKeyName
	for _, name := range opts.Names {
		if !existingNames[string(name)] {
			newNames = append(newNames, name)
		}
	}

	if len(newNames) == 1 {
		accountKeyDTO, serviceErr := s.createAccountKey(ctx, createAccountKeyOptions{
			requestID:  opts.RequestID,
			accountID:  accountDTO.ID(),
			accountDEK: accountDTO.DEK(),
			name:       newNames[0],
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create account key", "serviceErr", serviceErr)
			return nil, serviceErr
		}

		logger.InfoContext(ctx, "Found most account keys and created on account key",
			"foundCount", keysCount,
		)
		return append(accountKeyDTOs, accountKeyDTO), nil
	}

	newAccountKeyDTOs, serviceErr := s.createMultipleAccountKeys(ctx, createMultipleAccountKeysOptions{
		requestID:     opts.RequestID,
		accountID:     accountDTO.ID(),
		accountDEK:    accountDTO.DEK(),
		oidcConfigID:  oidcConfigDTO.ID(),
		oidcConfigDEK: oidcConfigDTO.DEK(),
		names:         newNames,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create multiple account keys", "serviceErr", serviceErr)
		return nil, serviceErr
	}

	logger.InfoContext(ctx, "Found some and created other account keys",
		"foundKeys", keysCount,
		"newKeys", len(newAccountKeyDTOs),
	)
	return append(accountKeyDTOs, newAccountKeyDTOs...), nil
}

type GetAccountKeyFnOptions struct {
	RequestID string
	Name      AppKeyName
}

func (s *Services) GetAccountKeyFn(
	ctx context.Context,
	opts GetAccountKeyFnOptions,
) func(kid string) (any, error) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetAccountKeyFn").With(
		"accountKeyName", opts.Name,
	)
	logger.InfoContext(ctx, "Getting account key function...")

	return func(kid string) (any, error) {
		publicJWK, err := s.cache.GetAccountPublicKey(ctx, cache.GetAccountPublicKeyOptions{
			RequestID: opts.RequestID,
			KID:       kid,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to get account key from cache", "error", err)
		}
		if publicJWK != nil {
			return publicJWK.ToUsableKey()
		}

		accountKey, err := s.database.FindAccountKeyByPublicKID(ctx, kid)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code != exceptions.CodeNotFound {
				logger.ErrorContext(ctx, "Failed to find app key", "error", err)
				return nil, serviceErr
			}

			logger.DebugContext(ctx, "App key not found")
			return nil, exceptions.NewNotFoundError()
		}

		if accountKey.Name != string(opts.Name) {
			logger.WarnContext(ctx, "App key not found for app key name", "appKeyName", opts.Name)
			return nil, exceptions.NewNotFoundError()
		}

		publicKey, err := dtos.DecodePublicKeyJSON(accountKey.JwtCryptoSuite, accountKey.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decode public key", "error", err)
			return nil, exceptions.NewServerError()
		}

		if err := s.cache.SaveAccountPublicKey(ctx, cache.SaveAccountPublicKeyOptions{
			RequestID: opts.RequestID,
			KID:       accountKey.PublicKid,
			PublicKey: publicKey,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to save account key to cache", "error", err)
			return nil, exceptions.NewServerError()
		}

		return publicKey.ToUsableKey()
	}
}

type GetDistributedJWKsOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) GetDistributedJWKs(
	ctx context.Context,
	opts GetDistributedJWKsOptions,
) ([]utils.JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetDistributedJWKs").With(
		"accountID", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting distributed JWKs...")

	accountKeys, err := s.database.FindDistributedAccountKeysByAccountID(ctx, opts.AccountID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account keys", "error", err)
			return nil, serviceErr
		}

		logger.DebugContext(ctx, "No account keys found")
		return nil, nil
	}

	jwks, serviceErr := utils.MapSliceWithErr(accountKeys, func(ak *database.AccountKey) (utils.JWK, *exceptions.ServiceError) {
		jwk, err := dtos.DecodePublicKeyJSON(ak.JwtCryptoSuite, ak.PublicKey)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to decode public key", "error", err)
			return nil, exceptions.NewServerError()
		}

		return jwk, nil
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map account keys to JWKs", "serviceErr", serviceErr)
		return nil, serviceErr
	}

	logger.InfoContext(ctx, "Distributed JWKs retrieved successfully")
	return jwks, nil
}
