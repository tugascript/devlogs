// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	ID      int32    `json:"id"`
	Version int32    `json:"version"`
	Roles   []string `json:"roles,omitempty"`
}

type userTokenClaims struct {
	User UserClaims `json:"user"`
	App  AppClaims  `json:"app"`
	jwt.RegisteredClaims
}

type UserTokenOptions struct {
	CryptoSuite     SupportedCryptoSuite
	Type            TokenType
	PrivateKey      interface{}
	KID             string
	AccountUsername string
	UserID          int32
	UserVersion     int32
	UserEmail       string
	AppProfileRoles []string
	AppID           int32
	AppClientID     string
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

func (t *Tokens) getUserTTL(tokenType TokenType) (int64, error) {
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
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserToken(opts UserTokenOptions) (string, error) {
	ttl, err := t.getUserTTL(opts.Type)
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
		User: UserClaims{
			ID:      opts.UserID,
			Version: opts.UserVersion,
			Roles:   opts.AppProfileRoles,
		},
		App: AppClaims{
			ID:       opts.AppID,
			ClientID: opts.AppClientID,
		},
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
	keyFn func(kid string) (interface{}, error),
	token string,
) (UserClaims, AppClaims, uuid.UUID, time.Time, error) {
	claims := new(userTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		return keyFn(kid)
	})
	if err != nil {
		return UserClaims{}, AppClaims{}, uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return UserClaims{}, AppClaims{}, uuid.Nil, time.Time{}, err
	}

	return claims.User, claims.App, tokenID, claims.ExpiresAt.Time, nil
}
