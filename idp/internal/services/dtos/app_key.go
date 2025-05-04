// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
	"errors"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AppKeyDTO struct {
	id             int
	appID          int
	accountID      int
	name           string
	jwtCryptoSuite tokens.SupportedCryptoSuite
	publicKey      utils.JWK
	publicKID      string
	privateKey     interface{}
}

func (ak *AppKeyDTO) ID() int {
	return ak.id
}

func (ak *AppKeyDTO) AppID() int {
	return ak.appID
}

func (ak *AppKeyDTO) AccountID() int {
	return ak.accountID
}

func (ak *AppKeyDTO) Name() string {
	return ak.name
}

func (ak *AppKeyDTO) JWTCryptoSuite() tokens.SupportedCryptoSuite {
	return ak.jwtCryptoSuite
}

func (ak *AppKeyDTO) PublicKey() utils.JWK {
	return ak.publicKey
}

func (ak *AppKeyDTO) PrivateKey() interface{} {
	return ak.privateKey
}

func (ak *AppKeyDTO) PublicKID() string {
	return ak.publicKID
}

func decodePublicKeyJSON(jwtCryptoSuite string, publicKey []byte) (utils.JWK, error) {
	switch jwtCryptoSuite {
	case string(tokens.SupportedCryptoSuiteES256):
		jwk := new(utils.ES256JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	case string(tokens.SupportedCryptoSuiteEd25519):
		jwk := new(utils.Ed25519JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	default:
		return nil, errors.New("unsupported crypto suite")
	}
}

func MapAppKeyWithKeysToDTO(
	appKey *database.AppKey,
	publicKeyJWK utils.JWK,
	privateKey interface{},
) (AppKeyDTO, *exceptions.ServiceError) {
	jwtCryptoSuite, serviceErr := getJwtCryptoSuite(appKey.JwtCryptoSuite)
	if serviceErr != nil {
		return AppKeyDTO{}, serviceErr
	}

	return AppKeyDTO{
		id:             int(appKey.ID),
		appID:          int(appKey.AppID),
		accountID:      int(appKey.AccountID),
		name:           appKey.Name,
		jwtCryptoSuite: jwtCryptoSuite,
		publicKey:      publicKeyJWK,
		privateKey:     privateKey,
		publicKID:      appKey.PublicKid,
	}, nil
}

func MapAppKeyToDTO(appKey *database.AppKey, privateKey interface{}) (AppKeyDTO, *exceptions.ServiceError) {
	publicKey, err := decodePublicKeyJSON(appKey.JwtCryptoSuite, appKey.PublicKey)
	if err != nil {
		return AppKeyDTO{}, exceptions.NewServerError()
	}

	jwtCryptoSuite, serviceErr := getJwtCryptoSuite(appKey.JwtCryptoSuite)
	if serviceErr != nil {
		return AppKeyDTO{}, serviceErr
	}

	return AppKeyDTO{
		id:             int(appKey.ID),
		appID:          int(appKey.AppID),
		accountID:      int(appKey.AccountID),
		name:           appKey.Name,
		jwtCryptoSuite: jwtCryptoSuite,
		publicKey:      publicKey,
		privateKey:     privateKey,
		publicKID:      appKey.PublicKid,
	}, nil
}
