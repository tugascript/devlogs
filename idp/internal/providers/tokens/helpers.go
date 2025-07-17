// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

func extractTokenKID(token *jwt.Token) (string, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", jwt.ErrInvalidKey
	}

	return kid, nil
}

func extractTokenAlgorithm(token *jwt.Token) (utils.SupportedCryptoSuite, error) {
	alg, ok := token.Header["alg"].(string)
	if !ok {
		return "", jwt.ErrInvalidKey
	}

	switch alg {
	case jwt.SigningMethodEdDSA.Alg():
		return utils.SupportedCryptoSuiteEd25519, nil
	case jwt.SigningMethodES256.Alg():
		return utils.SupportedCryptoSuiteES256, nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func buildPathAudience(backendDomain, path string) string {
	processedDomain := utils.ProcessURL(backendDomain)
	if path == "/" {
		return fmt.Sprintf("https://%s", processedDomain)
	}

	return fmt.Sprintf("https://%s/v1%s", processedDomain, path)
}

func getSigningMethod(cryptoSuite utils.SupportedCryptoSuite) (jwt.SigningMethod, error) {
	switch cryptoSuite {
	case utils.SupportedCryptoSuiteEd25519:
		return jwt.SigningMethodEdDSA, nil
	case utils.SupportedCryptoSuiteES256:
		return jwt.SigningMethodES256, nil
	default:
		return nil, fmt.Errorf("unsupported crypto suite: %s", cryptoSuite)
	}
}

type GetPublicJWK = func(kid string, cryptoSuite utils.SupportedCryptoSuite) (utils.JWK, error)

func buildVerifyKey(cryptoSuite utils.SupportedCryptoSuite, getPublicJWK GetPublicJWK) jwt.Keyfunc {
	return func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		jwk, err := getPublicJWK(kid, cryptoSuite)
		if err != nil {
			return nil, err
		}

		return jwk.ToUsableKey()
	}
}
