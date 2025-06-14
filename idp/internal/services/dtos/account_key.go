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

type AccountKeyDTO struct {
	id             int32
	oidcConfigID   int32
	accountID      int32
	name           string
	jwtCryptoSuite tokens.SupportedCryptoSuite
	publicKey      utils.JWK
	publicKID      string
	privateKey     interface{}
}

func (ak *AccountKeyDTO) ID() int32 {
	return ak.id
}

func (ak *AccountKeyDTO) OIDCConfigID() int32 {
	return ak.oidcConfigID
}

func (ak *AccountKeyDTO) AccountID() int32 {
	return ak.accountID
}

func (ak *AccountKeyDTO) Name() string {
	return ak.name
}

func (ak *AccountKeyDTO) JWTCryptoSuite() tokens.SupportedCryptoSuite {
	return ak.jwtCryptoSuite
}

func (ak *AccountKeyDTO) PublicKey() utils.JWK {
	return ak.publicKey
}

func (ak *AccountKeyDTO) PrivateKey() interface{} {
	return ak.privateKey
}

func (ak *AccountKeyDTO) PublicKID() string {
	return ak.publicKID
}

func DecodePublicKeyJSON(jwtCryptoSuite database.TokenCryptoSuite, publicKey []byte) (utils.JWK, error) {
	switch jwtCryptoSuite {
	case database.TokenCryptoSuiteES256:
		jwk := new(utils.ES256JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	case database.TokenCryptoSuiteEdDSA:
		jwk := new(utils.Ed25519JWK)
		if err := json.Unmarshal(publicKey, jwk); err != nil {
			return nil, err
		}
		return jwk, nil
	default:
		return nil, errors.New("unsupported crypto suite")
	}
}

func MapAccountKeyWithKeysToDTO(
	appKey *database.AccountKey,
	publicKeyJWK utils.JWK,
	privateKey any,
) (AccountKeyDTO, *exceptions.ServiceError) {
	jwtCryptoSuite, serviceErr := GetJwtCryptoSuite(appKey.JwtCryptoSuite)
	if serviceErr != nil {
		return AccountKeyDTO{}, serviceErr
	}

	return AccountKeyDTO{
		id:             appKey.ID,
		oidcConfigID:   appKey.OidcConfigID,
		accountID:      appKey.AccountID,
		name:           appKey.Name,
		jwtCryptoSuite: jwtCryptoSuite,
		publicKey:      publicKeyJWK,
		privateKey:     privateKey,
		publicKID:      appKey.PublicKid,
	}, nil
}

func MapAccountKeyToDTO(appKey *database.AccountKey, privateKey interface{}) (AccountKeyDTO, *exceptions.ServiceError) {
	publicKey, err := DecodePublicKeyJSON(appKey.JwtCryptoSuite, appKey.PublicKey)
	if err != nil {
		return AccountKeyDTO{}, exceptions.NewServerError()
	}

	jwtCryptoSuite, serviceErr := GetJwtCryptoSuite(appKey.JwtCryptoSuite)
	if serviceErr != nil {
		return AccountKeyDTO{}, serviceErr
	}

	return AccountKeyDTO{
		id:             appKey.ID,
		oidcConfigID:   appKey.OidcConfigID,
		accountID:      appKey.AccountID,
		name:           appKey.Name,
		jwtCryptoSuite: jwtCryptoSuite,
		publicKey:      publicKey,
		privateKey:     privateKey,
		publicKID:      appKey.PublicKid,
	}, nil
}
