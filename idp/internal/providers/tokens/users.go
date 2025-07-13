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

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type UserAuthClaims struct {
	UserID      uuid.UUID `json:"user_id"`
	UserVersion int32     `json:"user_version"`
	UserRoles   []string  `json:"user_roles"`
}

type userAuthTokenClaims struct {
	UserAuthClaims
	AppClaims
	Scope           string `json:"scope"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.RegisteredClaims
}

type UserAuthTokenOptions struct {
	CryptoSuite     utils.SupportedCryptoSuite
	TokenType       AuthTokenType
	AccountUsername string
	UserPublicID    uuid.UUID
	UserVersion     int32
	UserRoles       []string
	Scopes          []database.Scopes
	TokenSubject    string
	AppClientID     string
	AppVersion      int32
	Paths           []string
}

func (t *Tokens) getUserAuthTTL(tokenType AuthTokenType) (int64, error) {
	switch tokenType {
	case AuthTokenTypeAccess:
		return t.accessTTL, nil
	case AuthTokenTypeRefresh:
		return t.refreshTTL, nil
	case AuthTokenTypeClientCredentials:
		return t.accountCredentialsTTL, nil
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserAuthToken(opts UserAuthTokenOptions) (*jwt.Token, error) {
	ttl, err := t.getUserAuthTTL(opts.TokenType)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(ttl)))
	iss := fmt.Sprintf(
		"https://%s.%s",
		opts.AccountUsername,
		t.backendDomain,
	)

	method, err := getSigningMethod(opts.CryptoSuite)
	if err != nil {
		return nil, err
	}

	return jwt.NewWithClaims(method, userAuthTokenClaims{
		UserAuthClaims: UserAuthClaims{
			UserID:      opts.UserPublicID,
			UserVersion: opts.UserVersion,
			UserRoles:   opts.UserRoles,
		},
		AppClaims: AppClaims{
			ClientID: opts.AppClientID,
			Version:  opts.AppVersion,
		},
		Scope: strings.Join(utils.MapSlice(opts.Scopes, func(scope *database.Scopes) string {
			return string(*scope)
		}), " "),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: iss,
			Audience: utils.MapSlice(opts.Paths, func(path *string) string {
				return buildPathAudience(iss, *path)
			}),
			Subject:   opts.TokenSubject,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	}), nil
}

func (t *Tokens) VerifyUserAuthToken(
	token string,
	cryptoSuite utils.SupportedCryptoSuite,
	getPublicJWK GetPublicJWK,
) (UserAuthClaims, AppClaims, []database.Scopes, uuid.UUID, time.Time, error) {
	claims := new(userAuthTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, buildVerifyKey(cryptoSuite, getPublicJWK))
	if err != nil {
		return UserAuthClaims{}, AppClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return UserAuthClaims{}, AppClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	return claims.UserAuthClaims, claims.AppClaims, utils.MapSlice(strings.Split(claims.Scope, " "), func(scope *string) database.Scopes {
		return database.Scopes(*scope)
	}), tokenID, claims.ExpiresAt.Time, nil
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
		return t.confirmationTTL, nil
	case PurposeTokenTypeReset:
		return t.resetTTL, nil
	case PurposeTokenTypeOAuth:
		return t.oauthTTL, nil
	case PurposeTokenTypeTwoFA:
		return t.twoFATTL, nil
	default:
		return 0, errors.New("unsupported token type")
	}
}

func (t *Tokens) CreateUserPurposeToken(opts UserPurposeTokenOptions) (*jwt.Token, error) {
	ttl, err := t.getUserPurposeTTL(opts.TokenType)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(ttl)))
	iss := fmt.Sprintf(
		"https://%s.%s",
		opts.AccountUsername,
		t.backendDomain,
	)

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, userPurposeTokenClaims{
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
	}), nil
}

func (t *Tokens) VerifyUserPurposeToken(
	token string,
	getPublicJWK GetPublicJWK,
) (UserPurposeClaims, AppClaims, PurposeTokenType, error) {
	claims := new(userPurposeTokenClaims)

	_, err := jwt.ParseWithClaims(token, claims, buildVerifyKey(utils.SupportedCryptoSuiteEd25519, getPublicJWK))
	if err != nil {
		return UserPurposeClaims{}, AppClaims{}, "", err
	}

	return claims.UserPurposeClaims, claims.AppClaims, claims.Purpose, nil
}
