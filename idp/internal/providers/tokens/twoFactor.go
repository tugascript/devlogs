// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type TwoFAType string

const (
	TwoFATypeTOTP  TwoFAType = "totp"
	TwoFATypeEmail TwoFAType = "email"
)

type account2FATokenClaims struct {
	AccountClaims
	Purpose   TokenPurpose `json:"purpose"`
	TwoFAType TwoFAType    `json:"two_fa_type"`
	jwt.RegisteredClaims
}

type Account2FATokenOptions struct {
	PublicID  uuid.UUID
	Version   int32
	TwoFAType TwoFAType
}

func (t *Tokens) Create2FAToken(opts Account2FATokenOptions) *jwt.Token {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.twoFATTL)))

	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, account2FATokenClaims{
		AccountClaims: AccountClaims{
			AccountID:      opts.PublicID,
			AccountVersion: opts.Version,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{
				buildPathAudience(t.backendDomain, paths.V1+paths.AuthBase+paths.AuthLogin+paths.Auth2FA),
			},
			Issuer:    fmt.Sprintf("https://%s", t.backendDomain),
			Subject:   opts.PublicID.String(),
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
		Purpose:   TokenPurpose2FA,
		TwoFAType: opts.TwoFAType,
	})
}

func (t *Tokens) Verify2FAToken(token string, getPublicJWK GetPublicJWK) (AccountClaims, TwoFAType, error) {
	claims := new(account2FATokenClaims)

	if _, err := jwt.ParseWithClaims(
		token,
		claims,
		buildVerifyKey(utils.SupportedCryptoSuiteEd25519, getPublicJWK),
	); err != nil {
		return AccountClaims{}, "", err
	}

	return claims.AccountClaims, claims.TwoFAType, nil
}

func (t *Tokens) Get2FATTL() int64 {
	return t.twoFATTL
}
