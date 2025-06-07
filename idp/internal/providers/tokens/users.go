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

type UserScope = string

const (
	UserScopeConfirmation UserScope = "confirmation"
	UserScopeRefresh      UserScope = "refresh"
	UserScopeReset        UserScope = "reset"
	UserScope2FA          UserScope = "2fa"
)

type UserClaims struct {
	UserID      int32    `json:"user_id"`
	UserVersion int32    `json:"user_version"`
	Roles       []string `json:"roles,omitempty"`
}

type userTokenClaims struct {
	UserClaims
	AppClaims
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type UserTokenOptions struct {
	CryptoSuite     SupportedCryptoSuite
	Type            TokenType
	PrivateKey      any
	KID             string
	AccountUsername string
	UserID          int32
	UserVersion     int32
	UserEmail       string
	ProfileRoles    []string
	Scopes          []string
	AppID           int32
	AppClientID     string
	IDTTL           int64
}

func getUserSigningMethod(cryptoSuite SupportedCryptoSuite) (jwt.SigningMethod, error) {
	switch cryptoSuite {
	case SupportedCryptoSuiteES256:
		return jwt.SigningMethodES256, nil
	case SupportedCryptoSuiteEd25519:
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, errors.New("unsupported crypto suite")
	}
}

func (t *Tokens) getUserTTL(tokenType TokenType, idTTL int64) (int64, error) {
	switch tokenType {
	case TokenTypeAccess:
		return t.accessData.ttlSec, nil
	case TokenTypeRefresh:
		return t.refreshData.ttlSec, nil
	case TokenTypeConfirmation:
		return t.confirmationData.ttlSec, nil
	case TokenTypeReset:
		return t.resetData.ttlSec, nil
	case TokenTypeOAuth:
		return t.oauthData.ttlSec, nil
	case TokenTypeTwoFA:
		return t.twoFAData.ttlSec, nil
	case TokenTypeID:
		return idTTL, nil
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserToken(opts UserTokenOptions) (string, error) {
	ttl, err := t.getUserTTL(opts.Type, opts.IDTTL)
	if err != nil {
		return "", err
	}

	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(ttl)))
	iss := fmt.Sprintf(
		"https://%s.%s",
		opts.AccountUsername,
		t.backendDomain,
	)

	method, err := getUserSigningMethod(opts.CryptoSuite)
	if err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(method, userTokenClaims{
		UserClaims: UserClaims{
			UserID:      opts.UserID,
			UserVersion: opts.UserVersion,
			Roles:       opts.ProfileRoles,
		},
		AppClaims: AppClaims{
			AppID:    opts.AppID,
			ClientID: opts.AppClientID,
		},
		Scope: strings.Join(opts.Scopes, " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Audience:  jwt.ClaimStrings{iss},
			Subject:   opts.UserEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = opts.KID
	return token.SignedString(opts.PrivateKey)
}

func (t *Tokens) VerifyUserToken(
	keyFn func(kid string) (any, error),
	token string,
) (UserClaims, AppClaims, string, uuid.UUID, time.Time, error) {
	claims := new(userTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		return keyFn(kid)
	})
	if err != nil {
		return UserClaims{}, AppClaims{}, "", uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return UserClaims{}, AppClaims{}, "", uuid.Nil, time.Time{}, err
	}

	return claims.UserClaims, claims.AppClaims, claims.Scope, tokenID, claims.ExpiresAt.Time, nil
}
