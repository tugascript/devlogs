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
)

type accountCredentialsDynamicRegistrationClaims struct {
	AccountClaims
	Domain   string `json:"domain"`
	ClientID string `json:"client_id"`
	jwt.RegisteredClaims
}

type AccountCredentialsDynamicRegistrationTokenOptions struct {
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
	ClientID        string
}

func (t *Tokens) CreateAccountCredentialsDynamicRegistrationToken(
	opts AccountCredentialsDynamicRegistrationTokenOptions,
) *jwt.Token {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.dynamicRegistrationTTL)))
	return jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		accountCredentialsDynamicRegistrationClaims{
			AccountClaims: AccountClaims{
				AccountID:      opts.AccountPublicID,
				AccountVersion: opts.AccountVersion,
			},
			Domain:   opts.Domain,
			ClientID: opts.ClientID,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer: fmt.Sprintf("https://%s", t.backendDomain),
				Audience: []string{
					fmt.Sprintf("https://%s", opts.Domain),
				},
				Subject:   opts.Domain,
				IssuedAt:  iat,
				NotBefore: iat,
				ExpiresAt: exp,
				ID:        uuid.NewString(),
			},
		},
	)
}

func (t *Tokens) GetDynamicRegistrationTTL() int64 {
	return t.dynamicRegistrationTTL
}
