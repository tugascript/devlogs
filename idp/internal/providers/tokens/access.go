// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"crypto/ecdsa"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

var baseAccessPaths = []string{paths.Base}

type AccountAccessTokenOptions struct {
	PublicID     uuid.UUID
	Version      int32
	Scopes       []AccountScope
	TokenSubject string
}

func (t *Tokens) getAccessTokenPrivateKeyKIDAndTTL(tokenSubject, publicID string) (*ecdsa.PrivateKey, string, int64) {
	if tokenSubject != publicID {
		return t.accountCredentialsData.curKeyPair.privateKey,
			t.accountCredentialsData.curKeyPair.kid,
			t.accountCredentialsData.ttlSec
	}

	return t.accessData.curKeyPair.privateKey, t.accessData.curKeyPair.kid, t.accessData.ttlSec
}

func (t *Tokens) CreateAccessToken(opts AccountAccessTokenOptions) (string, error) {
	privateKey, kid, ttl := t.getAccessTokenPrivateKeyKIDAndTTL(opts.TokenSubject, opts.PublicID.String())
	return t.createAuthToken(accountAuthTokenOptions{
		method:          jwt.SigningMethodES256,
		privateKey:      privateKey,
		kid:             kid,
		ttlSec:          ttl,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		scopes:          opts.Scopes,
		tokenSubject:    opts.TokenSubject,
		paths:           baseAccessPaths,
	})
}

func (t *Tokens) VerifyAccessToken(token string) (AccountClaims, []AccountScope, error) {
	claims, err := verifyAuthToken(token, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return ecdsa.PublicKey{}, err
		}

		if t.accessData.prevPubKey != nil && t.accessData.prevPubKey.kid == kid {
			return t.accessData.prevPubKey.publicKey, nil
		}
		if t.accountCredentialsData.prevPubKey != nil && t.accountCredentialsData.prevPubKey.kid == kid {
			return t.accountCredentialsData.prevPubKey.publicKey, nil
		}
		if t.accessData.curKeyPair.kid == kid {
			return t.accessData.curKeyPair.publicKey, nil
		}
		if t.accountCredentialsData.curKeyPair.kid == kid {
			return t.accountCredentialsData.curKeyPair.publicKey, nil
		}

		return ecdsa.PublicKey{}, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, nil, err
	}

	scopes, err := splitAccountScopes(claims.Scope)
	if err != nil {
		return AccountClaims{}, nil, err
	}

	return claims.AccountClaims, scopes, nil
}

func (t *Tokens) GetAccessTTL() int64 {
	return t.accessData.ttlSec
}

func (t *Tokens) GetAccountCredentialsTTL() int64 {
	return t.accountCredentialsData.ttlSec
}
