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

func getCryptoSuite(isDistributed bool, cryptoSuite string) tokens.SupportedCryptoSuite {
	if isDistributed {
		return tokens.SupportedCryptoSuite(cryptoSuite)
	}
	return tokens.SupportedCryptoSuiteEd25519
}

type generateAppKeyKeyPairOptions struct {
	requestID   string
	accountID   int
	cryptoSuite tokens.SupportedCryptoSuite
	dek         string
}

func (s *Services) generateAppKeyKeyPair(
	ctx context.Context,
	opts generateAppKeyKeyPairOptions,
) (encryption.KeyPair, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "generateAppKeyKeyPair").With(
		"accountId", opts.accountID,
		"cryptoSuite", opts.cryptoSuite,
	)
	logger.InfoContext(ctx, "Generating app key key pair...")

	keyOpts := encryption.GenerateKeyPairOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		StoredDEK: opts.dek,
	}
	switch opts.cryptoSuite {
	case tokens.SupportedCryptoSuiteES256:
		logger.DebugContext(ctx, "Generating ES256 key pair...")
		keyPair, newDek, err := s.encrypt.GenerateES256KeyPair(ctx, keyOpts)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate ES256 key pair", "error", err)
			return encryption.KeyPair{}, "", exceptions.NewServerError()
		}

		return keyPair, newDek, nil
	case tokens.SupportedCryptoSuiteEd25519:
		logger.DebugContext(ctx, "Generating Ed25519 key pair...")
		keyPair, newDek, err := s.encrypt.GenerateEd25519KeyPair(ctx, keyOpts)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate Ed25519 key pair", "error", err)
			return encryption.KeyPair{}, "", exceptions.NewServerError()
		}

		return keyPair, newDek, nil
	default:
		logger.WarnContext(ctx, "Unsupported crypto suite", "cryptoSuite", opts.cryptoSuite)
		return encryption.KeyPair{}, "", exceptions.NewValidationError("unsupported crypto suite")
	}
}

type createAppKeyAndUpdateAppDekOptions struct {
	requestID   string
	accountID   int32
	appID       int32
	cryptoSuite string
	name        AppKeyName
	newDek      string
	publicKid   string
	publicKey   []byte
	privateKey  string
}

func (s *Services) createAppKeyAndUpdateAppDek(
	ctx context.Context,
	opts createAppKeyAndUpdateAppDekOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createAppKeyAndUpdateAppDek").With(
		"appID", opts.appID,
		"accountId", opts.accountID,
		"name", opts.name,
		"cryptoSuite", opts.cryptoSuite,
	)
	logger.InfoContext(ctx, "Creating app key and updating app DEK...")

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
		PublicKey:      opts.publicKey,
		PrivateKey:     opts.privateKey,
		IsDistributed:  isDistributedKey(opts.name),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.DebugContext(ctx, "Updating app DEK...")
	if err := qrs.UpdateAppDek(ctx, database.UpdateAppDekParams{
		Dek: opts.newDek,
		ID:  opts.appID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update app DEK", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App key created and app DEK updated successfully")
	return dtos.MapAppKeyToDTO(&appKey)
}

type createAppKeyOptions struct {
	requestID string
	accountID int32
	name      AppKeyName
	appDTO    dtos.AppDTO
}

func (s *Services) createAppKey(
	ctx context.Context,
	opts createAppKeyOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, appKeysLocation, "createAppKey").With(
		"appClientId", opts.appDTO.ClientID,
		"accountId", opts.accountID,
		"name", opts.name,
	)
	logger.InfoContext(ctx, "Creating app keys...")

	cryptoSuite := getCryptoSuite(isDistributedKey(opts.name), opts.appDTO.JwtCryptoSuite)
	keyPair, dek, serviceErr := s.generateAppKeyKeyPair(ctx, generateAppKeyKeyPairOptions{
		requestID:   opts.requestID,
		accountID:   int(opts.accountID),
		cryptoSuite: cryptoSuite,
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
			requestID:   opts.requestID,
			accountID:   opts.accountID,
			appID:       int32(opts.appDTO.ID()),
			cryptoSuite: opts.appDTO.JwtCryptoSuite,
			name:        opts.name,
			newDek:      dek,
			publicKid:   keyPair.Kid,
			publicKey:   publicKeyJSON,
			privateKey:  keyPair.EncryptedPrivateKey(),
		})
	}

	appKey, err := s.database.CreateAppKey(ctx, database.CreateAppKeyParams{
		AppID:          int32(opts.appDTO.ID()),
		AccountID:      opts.accountID,
		Name:           string(opts.name),
		JwtCryptoSuite: opts.appDTO.JwtCryptoSuite,
		PublicKid:      keyPair.Kid,
		PublicKey:      publicKeyJSON,
		PrivateKey:     keyPair.EncryptedPrivateKey(),
		IsDistributed:  isDistributedKey(opts.name),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create app key", "error", err)
		return dtos.AppKeyDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "App key created successfully")
	return dtos.MapAppKeyToDTO(&appKey)
}

type GetOrCreateAppKeyOptions struct {
	RequestID   string
	AppClientID string
	AccountID   int32
	Name        AppKeyName
}

func (s *Services) GetOrCreateAppKey(
	ctx context.Context,
	opts GetOrCreateAppKeyOptions,
) (dtos.AppKeyDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appKeysLocation, "GetOrCreateAppKeys").With(
		"appClientId", opts.AppClientID,
	)
	logger.InfoContext(ctx, "Getting or creating app keys...")

	app, serviceErr := s.GetAppByClientID(ctx, GetAppByClientIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		ClientID:  opts.AppClientID,
	})
	if serviceErr != nil {
		return dtos.AppKeyDTO{}, serviceErr
	}

	appKey, err := s.database.FindAppKeyByAppIDAndName(ctx, database.FindAppKeyByAppIDAndNameParams{
		AppID: int32(app.ID()),
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
			requestID: opts.RequestID,
			accountID: opts.AccountID,
			name:      opts.Name,
			appDTO:    app,
		})
	}

	logger.InfoContext(ctx, "App key found")
	return dtos.MapAppKeyToDTO(&appKey)
}
