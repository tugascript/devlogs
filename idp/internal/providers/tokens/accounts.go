// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"crypto/ed25519"
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
	AccountScopeEmail             AccountScope = "email"
	AccountScopeProfile           AccountScope = "profile"
	AccountScopeAdmin             AccountScope = "account:admin"
	AccountScopeUsersRead         AccountScope = "account:users:read"
	AccountScopeUsersWrite        AccountScope = "account:users:write"
	AccountScopeAppsRead          AccountScope = "account:apps:read"
	AccountScopeAppsWrite         AccountScope = "account:apps:write"
	AccountScopeCredentialsRead   AccountScope = "account:credentials:read"
	AccountScopeCredentialsWrite  AccountScope = "account:credentials:write"
	AccountScopeAuthProvidersRead AccountScope = "account:auth_providers:read"
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
	method          jwt.SigningMethod
	privateKey      any
	kid             string
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

func (t *Tokens) createAuthToken(opts accountAuthTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))

	token := jwt.NewWithClaims(opts.method, accountAuthTokenClaims{
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
	})
	token.Header["kid"] = opts.kid
	return token.SignedString(opts.privateKey)
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
	accountPublicID uuid.UUID
	accountVersion  int32
	path            string
	purpose         TokenPurpose
	ttlSec          int64
	privateKey      ed25519.PrivateKey
	kid             string
}

func (t *Tokens) createPurposeToken(opts accountPurposeTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, accountPurposeTokenClaims{
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
	token.Header["kid"] = opts.kid
	return token.SignedString(opts.privateKey)
}

func verifyPurposeToken(token string, pubKeyFn func(token *jwt.Token) (any, error)) (accountPurposeTokenClaims, error) {
	claims := new(accountPurposeTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, pubKeyFn); err != nil {
		return accountPurposeTokenClaims{}, err
	}

	return *claims, nil
}
