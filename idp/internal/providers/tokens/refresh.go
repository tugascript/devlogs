// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

var baseRefreshPaths = []string{paths.AuthBase + paths.AuthRefresh, paths.OAuthBase + paths.OAuthToken}

type AccountRefreshTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
	Scopes   []AccountScope
}

func (t *Tokens) CreateRefreshToken(opts AccountRefreshTokenOptions) (string, error) {
	return t.createAuthToken(accountAuthTokenOptions{
		method:          jwt.SigningMethodEdDSA,
		privateKey:      t.refreshData.curKeyPair.privateKey,
		kid:             t.refreshData.curKeyPair.kid,
		ttlSec:          t.refreshData.ttlSec,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		scopes:          opts.Scopes,
		tokenSubject:    opts.PublicID.String(),
		paths:           baseRefreshPaths,
	})
}

func (t *Tokens) VerifyRefreshToken(token string) (AccountClaims, []AccountScope, uuid.UUID, time.Time, error) {
	claims, err := verifyAuthToken(token, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.refreshData.prevPubKey != nil && t.refreshData.prevPubKey.kid == kid {
			return t.refreshData.prevPubKey.publicKey, nil
		}
		if t.refreshData.curKeyPair.kid == kid {
			return t.refreshData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	scopes, err := splitAccountScopes(claims.Scope)
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	return claims.AccountClaims, scopes, tokenID, claims.ExpiresAt.Time, nil
}

func (t *Tokens) GetRefreshTTL() int64 {
	return t.refreshData.ttlSec
}
