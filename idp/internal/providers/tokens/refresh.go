// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

var baseRefreshPaths = []string{paths.AuthBase + paths.AuthRefresh, paths.OAuthBase + paths.OAuthToken}

type AccountRefreshTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
	Scopes   []AccountScope
}

func (t *Tokens) CreateRefreshToken(opts AccountRefreshTokenOptions) (*jwt.Token, error) {
	return t.createAuthToken(accountAuthTokenOptions{
		cryptoSuite:     utils.SupportedCryptoSuiteEd25519,
		ttlSec:          t.refreshTTL,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		scopes:          opts.Scopes,
		tokenSubject:    opts.PublicID.String(),
		paths:           baseRefreshPaths,
	})
}

func (t *Tokens) VerifyRefreshToken(token string, getPublicJWK GetPublicJWK) (AccountClaims, []AccountScope, uuid.UUID, time.Time, error) {
	claims, err := verifyAuthToken(token, buildVerifyKey(utils.SupportedCryptoSuiteEd25519, getPublicJWK))
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
	return t.refreshTTL
}
