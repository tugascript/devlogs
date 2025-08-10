// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type GetDecryptedSecret = func(secretID string) ([]byte, error)

func (t *Tokens) VerifyJWTBearerGrantToken(
	token string,
	getPublicJWK GetPublicJWK,
	getDecodedSecret GetDecryptedSecret,
) (jwt.RegisteredClaims, utils.SupportedCryptoSuite, string, error) {
	var claims jwt.RegisteredClaims
	var cryptoSuite utils.SupportedCryptoSuite
	var kid string
	var err error
	if _, err = jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		kid, err = extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		cryptoSuite, err = extractTokenAlgorithm(token)
		if err != nil {
			return nil, err
		}

		if cryptoSuite == utils.SupportedCryptoSuiteHS256 {
			return getDecodedSecret(kid)
		}

		var jwk utils.JWK
		jwk, err = getPublicJWK(kid, cryptoSuite)
		if err != nil {
			return nil, err
		}

		return jwk.ToUsableKey()
	}); err != nil {
		return jwt.RegisteredClaims{}, "", "", err
	}

	return claims, cryptoSuite, kid, nil
}
