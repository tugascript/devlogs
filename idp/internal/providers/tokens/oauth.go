// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

func (t *Tokens) CreateOAuthToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(accountTokenOptions{
		method:         jwt.SigningMethodEdDSA,
		privateKey:     t.oauthData.curKeyPair.privateKey,
		kid:            t.oauthData.curKeyPair.kid,
		ttlSec:         t.oauthData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
		scopes:         []AccountScope{AccountScopeOAuth},
	})
}

func (t *Tokens) VerifyOAuthToken(token string) (AccountClaims, []AccountScope, error) {
	claims, err := verifyToken(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.oauthData.prevPubKey != nil && t.oauthData.prevPubKey.kid == kid {
			return t.oauthData.prevPubKey.publicKey, nil
		}
		if t.oauthData.curKeyPair.kid == kid {
			return t.oauthData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, nil, err
	}

	scopes, err := splitAccountScopes(claims.Scope)
	if err != nil {
		return AccountClaims{}, nil, err
	}

	return claims.Account, scopes, nil
}

func (t *Tokens) GetOAuthTTL() int64 {
	return t.oauthData.ttlSec
}
