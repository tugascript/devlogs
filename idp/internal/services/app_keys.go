// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
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
)

func isDistributedKey(name AppKeyName) bool {
	return name == AppKeyNameAccess || name == AppKeyNameClient || name == AppKeyNameID || name == AppKeyNameOAuth
}

func getCryptoSuite(isDistributed bool, cryptoSuite tokens.SupportedCryptoSuite) tokens.SupportedCryptoSuite {
	if isDistributed {
		return cryptoSuite
	}
	return tokens.SupportedCryptoSuiteEd25519
}

type generateAppKeyKeyPairOptions struct {
	requestID   string
	cryptoSuite tokens.SupportedCryptoSuite
	dek         string
}

func (s *Services) generateAppKeyKeyPair(
	ctx context.Context,
	opts generateAppKeyKeyPairOptions,
) (encryption.KeyPair, interface{}, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "generateAppKeyKeyPair").With(
		"cryptoSuite", opts.cryptoSuite,
	)
	logger.InfoContext(ctx, "Generating app key key pair...")

	keyOpts := encryption.GenerateKeyPairOptions{
		RequestID: opts.requestID,
		StoredDEK: opts.dek,
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

type createAppKeyAndUpdateAppDekOptions struct {
	requestID           string
	accountID           int32
	appID               int32
	cryptoSuite         string
	name                AppKeyName
	newDek              string
	publicKid           string
	jsonPublicKey       []byte
	encryptedPrivateKey string
	publicKey           utils.JWK
	privateKey          interface{}
}

func (s *Services) createAppKeyAndUpdateAppDek(
	ctx context.Context,
	opts createAppKeyAndUpdateAppDekOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createAppKeyAndUpdateAppDek").With(
		"appId", opts.appID,
		"accountId", opts.accountID,
		"name", opts.name,
		"cryptoSuite", opts.cryptoSuite,
	)
	logger.InfoContext(ctx, "Creating app key and updating app StoredDEK...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	appKey, err := qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
		AppID:          opts.appID,
		AccountID:      opts.accountID,
		Name:           string(opts.name),
		JwtCryptoSuite: opts.cryptoSuite,
		PublicKid:      opts.publicKid,
		PublicKey:      opts.jsonPublicKey,
		PrivateKey:     opts.encryptedPrivateKey,
		IsDistributed:  isDistributedKey(opts.name),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.DebugContext(ctx, "Updating app StoredDEK...")
	if err := qrs.UpdateAppDek(ctx, database.UpdateAppDekParams{
		Dek: opts.newDek,
		ID:  opts.appID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update app StoredDEK", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App key created and app StoredDEK updated successfully")
	return dtos.MapAppKeyWithKeysToDTO(&appKey, opts.publicKey, opts.privateKey)
}

type createAppKeyOptions struct {
	requestID      string
	accountID      int32
	name           AppKeyName
	appID          int32
	appDEK         string
	jwtCryptoSuite tokens.SupportedCryptoSuite
}

func (s *Services) createAppKey(
	ctx context.Context,
	opts createAppKeyOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createAppKey").With(
		"appId", opts.appID,
		"accountId", opts.accountID,
		"name", opts.name,
	)
	logger.InfoContext(ctx, "Creating app keys...")

	cryptoSuite := getCryptoSuite(isDistributedKey(opts.name), opts.jwtCryptoSuite)
	keyPair, privateKey, dek, serviceErr := s.generateAppKeyKeyPair(ctx, generateAppKeyKeyPairOptions{
		requestID:   opts.requestID,
		cryptoSuite: cryptoSuite,
		dek:         opts.appDEK,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to generate app key key pair", "error", serviceErr)
		return dtos.AppKeyDTO{}, serviceErr
	}

	publicKeyJSON, err := keyPair.PublicKey.ToJSON()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to convert public key to JSON", "error", err)
		return dtos.AppKeyDTO{}, exceptions.NewServerError()
	}

	if dek != "" {
		return s.createAppKeyAndUpdateAppDek(ctx, createAppKeyAndUpdateAppDekOptions{
			requestID:           opts.requestID,
			accountID:           opts.accountID,
			appID:               opts.appID,
			cryptoSuite:         string(opts.jwtCryptoSuite),
			name:                opts.name,
			newDek:              dek,
			publicKid:           keyPair.KID,
			jsonPublicKey:       publicKeyJSON,
			encryptedPrivateKey: keyPair.EncryptedPrivateKey(),
			publicKey:           keyPair.PublicKey,
			privateKey:          privateKey,
		})
	}

	appKey, err := s.database.CreateAppKey(ctx, database.CreateAppKeyParams{
		AppID:          opts.appID,
		AccountID:      opts.accountID,
		Name:           string(opts.name),
		JwtCryptoSuite: string(opts.jwtCryptoSuite),
		PublicKid:      keyPair.KID,
		PublicKey:      publicKeyJSON,
		PrivateKey:     keyPair.EncryptedPrivateKey(),
		IsDistributed:  isDistributedKey(opts.name),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App key created successfully")
	return dtos.MapAppKeyWithKeysToDTO(&appKey, keyPair.PublicKey, privateKey)
}

func (s *Services) decryptPrivateKey(
	ctx context.Context,
	requestID string,
	appKey *database.AppKey,
	appDEK string,
) (interface{}, *exceptions.ServiceError) {
	logger := s.buildLogger(requestID, appKeysLocation, "decryptPrivateKey").With(
		"appID", appKey.AppID,
		"appKeyID", appKey.ID,
	)
	logger.InfoContext(ctx, "Decrypting private key...")

	opts := encryption.DecryptPrivateKeyOptions{
		RequestID:    requestID,
		EncryptedKey: appKey.PrivateKey,
		StoredDEK:    appDEK,
	}
	var privateKey interface{}
	var newDEK string
	var err error
	switch appKey.JwtCryptoSuite {
	case string(tokens.SupportedCryptoSuiteES256):
		privateKey, newDEK, err = s.encrypt.DecryptES256PrivateKey(ctx, opts)
	case string(tokens.SupportedCryptoSuiteEd25519):
		privateKey, newDEK, err = s.encrypt.DecryptEd25519PrivateKey(ctx, opts)
	default:
		logger.WarnContext(ctx, "Unsupported crypto suite", "cryptoSuite", appKey.JwtCryptoSuite)
		return nil, exceptions.NewForbiddenError()
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", err)
		return nil, exceptions.NewServerError()
	}

	if newDEK != "" {
		if err := s.database.UpdateAppDek(ctx, database.UpdateAppDekParams{
			Dek: newDEK,
			ID:  appKey.AppID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update app StoredDEK", "error", err)
			return nil, exceptions.FromDBError(err)
		}
	}

	logger.InfoContext(ctx, "Private key decrypted successfully")
	return privateKey, nil
}

type GetAppKeyOptions struct {
	RequestID string
	AppID     int32
	AppDEK    string
	Name      AppKeyName
}

func (s *Services) GetAppKey(
	ctx context.Context,
	opts GetAppKeyOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetAppKey").With(
		"appId", opts.AppID,
	)
	logger.InfoContext(ctx, "Getting app key...")

	appKey, err := s.database.FindAppKeyByAppIDAndName(ctx, database.FindAppKeyByAppIDAndNameParams{
		AppID: opts.AppID,
		Name:  string(opts.Name),
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app key", "error", err)
			return dtos.AppKeyDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "App key not found")
		return dtos.AppKeyDTO{}, exceptions.NewNotFoundError()
	}

	privateKey, serviceErr := s.decryptPrivateKey(ctx, opts.RequestID, &appKey, opts.AppDEK)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", serviceErr)
		return dtos.AppKeyDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App key found")
	return dtos.MapAppKeyToDTO(&appKey, privateKey)
}

type GetOrCreateAppKeyOptions struct {
	RequestID         string
	AppID             int32
	AppDEK            string
	AppJwtCryptoSuite tokens.SupportedCryptoSuite
	AccountID         int32
	Name              AppKeyName
}

func (s *Services) GetOrCreateAppKey(
	ctx context.Context,
	opts GetOrCreateAppKeyOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetOrCreateAppKeys").With(
		"appId", opts.AppID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating app keys...")

	appKey, err := s.database.FindAppKeyByAppIDAndName(ctx, database.FindAppKeyByAppIDAndNameParams{
		AppID: opts.AppID,
		Name:  string(opts.Name),
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find app key", "error", err)
			return dtos.AppKeyDTO{}, serviceErr
		}

		logger.DebugContext(ctx, "App key not found, creating new one")
		return s.createAppKey(ctx, createAppKeyOptions{
			requestID:      opts.RequestID,
			accountID:      opts.AccountID,
			name:           opts.Name,
			appID:          opts.AppID,
			appDEK:         opts.AppDEK,
			jwtCryptoSuite: opts.AppJwtCryptoSuite,
		})
	}

	privateKey, serviceErr := s.decryptPrivateKey(ctx, opts.RequestID, &appKey, opts.AppDEK)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to decrypt private key", "error", serviceErr)
		return dtos.AppKeyDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "App key found")
	return dtos.MapAppKeyToDTO(&appKey, privateKey)
}

type AppKeyParam struct {
	Name           AppKeyName
	JwtCryptoSuite tokens.SupportedCryptoSuite
}

type GetOrCreateAppKeysOptions struct {
	RequestID    string
	AppID        int32
	AppDEK       string
	AccountID    int32
	AppKeyParams []AppKeyParam
}

func (s *Services) GetOrCreateAppKeys(
	ctx context.Context,
	opts GetOrCreateAppKeysOptions,
) (map[AppKeyName]dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetOrCreateAppKeys").With(
		"appId", opts.AppID,
		"accountId", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting or creating app keys...")

	appKeys, err := s.database.FindAppKeysByNamesAndAppID(ctx, database.FindAppKeysByNamesAndAppIDParams{
		AppID: opts.AppID,
		Names: utils.MapSlice(opts.AppKeyParams, func(t *AppKeyParam) string {
			return string(t.Name)
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find app keys", "error", err)
		return nil, exceptions.FromDBError(err)
	}

	appKeyDTOs, serviceErr := utils.MapSliceWithErrorToMap(
		appKeys,
		func(ak *database.AppKey) (AppKeyName, dtos.AppKeyDTO, *exceptions.ServiceError) {
			privateKey, serviceErr := s.decryptPrivateKey(ctx, opts.RequestID, ak, opts.AppDEK)
			if serviceErr != nil {
				logger.ErrorContext(ctx, "Failed to decrypt private key", "error", serviceErr)
				return "", dtos.AppKeyDTO{}, serviceErr
			}

			appKeyDTO, serviceErr := dtos.MapAppKeyToDTO(ak, privateKey)
			return AppKeyName(ak.Name), appKeyDTO, serviceErr
		})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map app keys to DTOs", "error", serviceErr)
		return nil, serviceErr
	}

	if len(appKeyDTOs) == len(opts.AppKeyParams) {
		logger.InfoContext(ctx, "All app keys found")
		return appKeyDTOs, nil
	}

	logger.DebugContext(ctx, "Some app keys not found, creating new ones")
	namesMap := make(map[AppKeyName]bool)
	for _, ak := range appKeys {
		namesMap[AppKeyName(ak.Name)] = true
	}

	newAppKeys := make([]AppKeyParam, 0)
	for _, ak := range opts.AppKeyParams {
		if namesMap[ak.Name] {
			continue
		}

		newAppKeys = append(newAppKeys, ak)
	}

	newCount := len(newAppKeys)
	if newCount == 0 {
		logger.InfoContext(ctx, "No new app keys to create")
		return appKeyDTOs, nil
	}
	if newCount == 1 {
		ak := newAppKeys[0]
		newAppKey, serviceErr := s.createAppKey(ctx, createAppKeyOptions{
			requestID:      opts.RequestID,
			accountID:      opts.AccountID,
			name:           ak.Name,
			appID:          opts.AppID,
			appDEK:         opts.AppDEK,
			jwtCryptoSuite: ak.JwtCryptoSuite,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", serviceErr)
			return nil, serviceErr
		}

		appKeyDTOs[ak.Name] = newAppKey
		return appKeyDTOs, nil
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return nil, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	var updatedDEK string
	for _, prms := range newAppKeys {
		cryptoSuite := getCryptoSuite(isDistributedKey(prms.Name), prms.JwtCryptoSuite)
		var keyPair encryption.KeyPair
		var privateKey interface{}
		var newDEK string
		keyPair, privateKey, newDEK, serviceErr = s.generateAppKeyKeyPair(ctx, generateAppKeyKeyPairOptions{
			requestID:   opts.RequestID,
			cryptoSuite: cryptoSuite,
			dek:         opts.AppDEK,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to generate app key key pair", "error", serviceErr)
			return nil, serviceErr
		}

		var publicKeyJSON []byte
		publicKeyJSON, err = keyPair.PublicKey.ToJSON()
		if err != nil {
			logger.ErrorContext(ctx, "Failed to convert public key to JSON", "error", err)
			return nil, exceptions.NewServerError()
		}

		if newDEK != "" {
			updatedDEK = newDEK
		}

		var appKey database.AppKey
		appKey, err = qrs.CreateAppKey(ctx, database.CreateAppKeyParams{
			AppID:          opts.AppID,
			AccountID:      opts.AccountID,
			Name:           string(prms.Name),
			JwtCryptoSuite: string(prms.JwtCryptoSuite),
			PublicKid:      keyPair.KID,
			PublicKey:      publicKeyJSON,
			PrivateKey:     keyPair.EncryptedPrivateKey(),
			IsDistributed:  false,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create app key", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return nil, serviceErr
		}

		var appKeyDTO dtos.AppKeyDTO
		appKeyDTO, serviceErr = dtos.MapAppKeyToDTO(&appKey, privateKey)
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to map app key to DTO", "error", serviceErr)
			return nil, serviceErr
		}

		appKeyDTOs[prms.Name] = appKeyDTO
	}

	if updatedDEK != "" {
		logger.DebugContext(ctx, "Updating app StoredDEK...")
		if err = qrs.UpdateAppDek(ctx, database.UpdateAppDekParams{
			Dek: updatedDEK,
			ID:  opts.AppID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update app StoredDEK", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return nil, serviceErr
		}
	}

	logger.InfoContext(ctx, "App keys created successfully")
	return appKeyDTOs, nil
}
