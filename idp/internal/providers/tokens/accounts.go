// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccountScope = string

const (
	AccountScopeAdmin             AccountScope = "admin"
	AccountScopeClientCredentials AccountScope = "client_credentials"

	AccountScope2FA          AccountScope = "2fa"
	AccountScopeOAuth        AccountScope = "oauth"
	AccountScopeConfirmation AccountScope = "confirmation"
	AccountScopeRefresh      AccountScope = "refresh"
	AccountScopeReset        AccountScope = "reset"

	AccountScopeUsersRead  AccountScope = "users:read"
	AccountScopeUsersWrite AccountScope = "users:write"

	AccountScopeAppsRead  AccountScope = "apps:read"
	AccountScopeAppsWrite AccountScope = "apps:write"
)

type AccountTokenOptions struct {
	ID       int32
	Version  int32
	Email    string
	Audience string
	Scopes   []AccountScope
}

type AccountClaims struct {
	ID      int32 `json:"id"`
	Version int32 `json:"version"`
}

type accountTokenClaims struct {
	Account AccountClaims `json:"account"`
	Scope   string        `json:"scope"`
	jwt.RegisteredClaims
}

type accountTokenOptions struct {
	method         jwt.SigningMethod
	privateKey     any
	kid            string
	ttlSec         int64
	accountID      int32
	accountVersion int32
	accountEmail   string
	audience       string
	scopes         []AccountScope
}

func processAccountScopes(scopes []AccountScope) (string, error) {
	if scopes == nil {
		return "", errors.New("missing scopes")
	}

	return strings.Join(scopes, " "), nil
}

func splitAccountScopes(scopes string) ([]AccountScope, error) {
	if scopes == "" {
		return nil, errors.New("scopes are empty")
	}

	return strings.Split(scopes, " "), nil
}

func (t *Tokens) getDefaultAudience(aud string) jwt.ClaimStrings {
	if aud == "" {
		return jwt.ClaimStrings{fmt.Sprintf("https://%s", t.frontendDomain)}
	}

	return jwt.ClaimStrings{aud}
}

func (t *Tokens) createToken(opts accountTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))
	scopes, err := processAccountScopes(opts.scopes)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(opts.method, accountTokenClaims{
		Account: AccountClaims{
			ID:      opts.accountID,
			Version: opts.accountVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.frontendDomain,
			Audience:  t.getDefaultAudience(opts.audience),
			Subject:   opts.accountEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
		Scope: scopes,
	})
	token.Header["kid"] = opts.kid
	return token.SignedString(opts.privateKey)
}

func verifyToken(token string, pubKeyFn func(token *jwt.Token) (any, error)) (accountTokenClaims, error) {
	claims := new(accountTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, pubKeyFn); err != nil {
		return accountTokenClaims{}, err
	}

	return *claims, nil
}
