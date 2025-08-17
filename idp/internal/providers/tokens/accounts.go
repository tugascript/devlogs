// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AccountScope = string

const (
	AccountScopeEmail                   AccountScope = "email"
	AccountScopeProfile                 AccountScope = "profile"
	AccountScopeAdmin                   AccountScope = "account:admin"
	AccountScopeUsersRead               AccountScope = "account:users:read"
	AccountScopeUsersWrite              AccountScope = "account:users:write"
	AccountScopeAppsRead                AccountScope = "account:apps:read"
	AccountScopeAppsWrite               AccountScope = "account:apps:write"
	AccountScopeAppsConfigsRead         AccountScope = "account:apps:configs:read"
	AccountScopeAppsConfigsWrite        AccountScope = "account:apps:configs:write"
	AccountScopeCredentialsRead         AccountScope = "account:credentials:read"
	AccountScopeCredentialsWrite        AccountScope = "account:credentials:write"
	AccountScopeCredentialsConfigsRead  AccountScope = "account:credentials:configs:read"
	AccountScopeCredentialsConfigsWrite AccountScope = "account:credentials:configs:write"
	AccountScopeAuthProvidersRead       AccountScope = "account:auth_providers:read"
)

var baseAuthScopes = []AccountScope{AccountScopeEmail, AccountScopeProfile}

const baseAuthScope = AccountScopeEmail + " " + AccountScopeProfile

type AccountClaims struct {
	AccountID      uuid.UUID `json:"account_id"`
	AccountVersion int32     `json:"account_version"`
}

type accountAuthTokenClaims struct {
	AccountClaims
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type accountPurposeTokenClaims struct {
	AccountClaims
	Purpose TokenPurpose `json:"purpose"`
	jwt.RegisteredClaims
}

type accountAuthTokenOptions struct {
	cryptoSuite     utils.SupportedCryptoSuite
	ttlSec          int64
	accountPublicID uuid.UUID
	accountVersion  int32
	tokenSubject    string
	scopes          []AccountScope
	paths           []string
}

func processAccountScopes(scopes []AccountScope) string {
	if scopes == nil {
		return baseAuthScope
	}
	if len(scopes) >= 2 && slices.ContainsFunc(scopes, func(scope AccountScope) bool {
		return scope == "email" || scope == "profile"
	}) {
		return strings.Join(scopes, " ")
	}

	return strings.Join(append(baseAuthScopes, scopes...), " ")
}

func splitAccountScopes(scope string) ([]AccountScope, error) {
	if scope == "" {
		return nil, errors.New("scopes are empty")
	}

	return strings.Split(scope, " "), nil
}

func (t *Tokens) createAuthToken(opts accountAuthTokenOptions) (*jwt.Token, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))
	method, err := getSigningMethod(opts.cryptoSuite)
	if err != nil {
		return nil, err
	}

	return jwt.NewWithClaims(method, accountAuthTokenClaims{
		AccountClaims: AccountClaims{
			AccountID:      opts.accountPublicID,
			AccountVersion: opts.accountVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: fmt.Sprintf("https://%s", t.backendDomain),
			Audience: utils.MapSlice(opts.paths, func(path *string) string {
				return buildPathAudience(t.backendDomain, *path)
			}),
			Subject:   opts.tokenSubject,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
		Scope: processAccountScopes(opts.scopes),
	}), nil

}

func verifyAuthToken(token string, pubKeyFn func(token *jwt.Token) (any, error)) (accountAuthTokenClaims, error) {
	claims := new(accountAuthTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, pubKeyFn); err != nil {
		return accountAuthTokenClaims{}, err
	}

	return *claims, nil
}

type AccountPurposeTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
	Path     string
	Subject  string
	Purpose  TokenPurpose
}

type accountPurposeTokenOptions struct {
	ttlSec          int64
	accountPublicID uuid.UUID
	accountVersion  int32
	path            string
	purpose         TokenPurpose
}

func (t *Tokens) createPurposeToken(opts accountPurposeTokenOptions) *jwt.Token {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, accountPurposeTokenClaims{
		AccountClaims: AccountClaims{
			AccountID:      opts.accountPublicID,
			AccountVersion: opts.accountVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{buildPathAudience(t.backendDomain, opts.path)},
			Issuer:    fmt.Sprintf("https://%s", t.backendDomain),
			Subject:   opts.accountPublicID.String(),
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
		Purpose: opts.purpose,
	})
}

func parsePurposeToken(token string, pubKeyFn func(token *jwt.Token) (any, error)) (accountPurposeTokenClaims, error) {
	claims := new(accountPurposeTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, pubKeyFn); err != nil {
		return accountPurposeTokenClaims{}, err
	}

	return *claims, nil
}

func (t *Tokens) VerifyPurposeToken(token string, purpose TokenPurpose, getPublicJWK GetPublicJWK) (AccountClaims, error) {
	claims, err := parsePurposeToken(token, buildVerifyKey(utils.SupportedCryptoSuiteEd25519, getPublicJWK))
	if err != nil {
		return AccountClaims{}, err
	}
	if claims.Purpose != purpose {
		return AccountClaims{}, fmt.Errorf("invalid purpose: %s", claims.Purpose)
	}

	return claims.AccountClaims, nil
}
