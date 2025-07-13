// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

var baseAccessPaths = []string{paths.Base}

type AccountAccessTokenOptions struct {
	PublicID     uuid.UUID
	Version      int32
	Scopes       []AccountScope
	TokenSubject string
}

func (t *Tokens) getAccessTokenTTL(tokenSubject, publicID string) int64 {
	if tokenSubject != publicID {
		return t.accountCredentialsTTL
	}

	return t.accessTTL
}

func (t *Tokens) CreateAccessToken(opts AccountAccessTokenOptions) (*jwt.Token, error) {
	return t.createAuthToken(accountAuthTokenOptions{
		cryptoSuite:     utils.SupportedCryptoSuiteES256,
		ttlSec:          t.getAccessTokenTTL(opts.TokenSubject, opts.PublicID.String()),
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		scopes:          opts.Scopes,
		tokenSubject:    opts.TokenSubject,
		paths:           baseAccessPaths,
	})
}

func (t *Tokens) VerifyAccessToken(token string, getPublicJWK GetPublicJWK) (AccountClaims, []AccountScope, error) {
	claims, err := verifyAuthToken(token, buildVerifyKey(utils.SupportedCryptoSuiteES256, getPublicJWK))
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
	return t.accessTTL
}

func (t *Tokens) GetAccountCredentialsTTL() int64 {
	return t.accountCredentialsTTL
}
