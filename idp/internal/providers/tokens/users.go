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
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type UserAuthClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	UserVersion int32     `json:"user_version"`
	Roles       []string  `json:"user_roles"`
}

type userAuthTokenClaims struct {
	UserAuthClaims
	AppClaims
	Scope string `json:"scope"`
	jwt.RegisteredClaims
}

type UserAuthTokenOptions struct {
	CryptoSuite     SupportedCryptoSuite
	TokenType       AuthTokenType
	PrivateKey      any
	KID             string
	AccountUsername string
	UserPublicID    uuid.UUID
	UserVersion     int32
	ProfileRoles    []string
	Scopes          []string
	TokenSubject    string
	AppClientID     string
	AppVersion      int32
	Paths           []string
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

func (t *Tokens) getUserAuthTTL(tokenType AuthTokenType) (int64, error) {
	switch tokenType {
	case AuthTokenTypeAccess:
		return t.accessData.ttlSec, nil
	case AuthTokenTypeRefresh:
		return t.refreshData.ttlSec, nil
	case AuthTokenTypeClientCredentials:
		return t.accountCredentialsData.ttlSec, nil
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserAuthToken(opts UserAuthTokenOptions) (string, error) {
	ttl, err := t.getUserAuthTTL(opts.TokenType)
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

	token := jwt.NewWithClaims(method, userAuthTokenClaims{
		UserAuthClaims: UserAuthClaims{
			UserID:      opts.UserPublicID,
			UserVersion: opts.UserVersion,
			Roles:       opts.ProfileRoles,
		},
		AppClaims: AppClaims{
			ClientID: opts.AppClientID,
			Version:  opts.AppVersion,
		},
		Scope: strings.Join(opts.Scopes, " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: iss,
			Audience: jwt.ClaimStrings(utils.MapSlice(opts.Paths, func(path *string) string {
				return buildPathAudience(iss, *path)
			})),
			Subject:   opts.TokenSubject,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = opts.KID
	return token.SignedString(opts.PrivateKey)
}

func (t *Tokens) VerifyUserAuthToken(
	keyFn func(kid string) (any, error),
	token string,
) (UserAuthClaims, AppClaims, []string, uuid.UUID, time.Time, error) {
	claims := new(userAuthTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		return keyFn(kid)
	})
	if err != nil {
		return UserAuthClaims{}, AppClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return UserAuthClaims{}, AppClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	return claims.UserAuthClaims, claims.AppClaims, strings.Split(claims.Scope, " "), tokenID, claims.ExpiresAt.Time, nil
}

type UserPurposeClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	UserVersion int32     `json:"user_version"`
}

type userPurposeTokenClaims struct {
	UserPurposeClaims
	AppClaims
	Purpose PurposeTokenType `json:"purpose"`
	jwt.RegisteredClaims
}

type UserPurposeTokenOptions struct {
	TokenType       PurposeTokenType
	PrivateKey      any
	KID             string
	AccountUsername string
	UserPublicID    uuid.UUID
	UserVersion     int32
	AppClientID     string
	AppVersion      int32
	Path            string
}

func (t *Tokens) getUserPurposeTTL(tokenType PurposeTokenType) (int64, error) {
	switch tokenType {
	case PurposeTokenTypeConfirmation:
		return t.confirmationData.ttlSec, nil
	case PurposeTokenTypeReset:
		return t.resetData.ttlSec, nil
	case PurposeTokenTypeOAuth:
		return t.oauthData.ttlSec, nil
	case PurposeTokenTypeTwoFA:
		return t.twoFAData.ttlSec, nil
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserPurposeToken(opts UserPurposeTokenOptions) (string, error) {
	ttl, err := t.getUserPurposeTTL(opts.TokenType)
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

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, userPurposeTokenClaims{
		UserPurposeClaims: UserPurposeClaims{
			UserID:      opts.UserPublicID,
			UserVersion: opts.UserVersion,
		},
		AppClaims: AppClaims{
			ClientID: opts.AppClientID,
			Version:  opts.AppVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: iss,
			Audience: jwt.ClaimStrings{
				buildPathAudience(iss, opts.Path),
			},
			Subject:   opts.UserPublicID.String(),
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
		Purpose: opts.TokenType,
	})
	token.Header["kid"] = opts.KID
	return token.SignedString(opts.PrivateKey)
}

func (t *Tokens) VerifyUserPurposeToken(
	keyFn func(kid string) (any, error),
	token string,
) (UserPurposeClaims, AppClaims, PurposeTokenType, error) {
	claims := new(userPurposeTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		return keyFn(kid)
	})
	if err != nil {
		return UserPurposeClaims{}, AppClaims{}, "", err
	}

	return claims.UserPurposeClaims, claims.AppClaims, claims.Purpose, nil
}
