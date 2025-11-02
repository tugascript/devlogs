// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"context"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const dynamicRegistrationIATLocation = "dynamic_registration_iat"

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
	iss := fmt.Sprintf("https://%s", t.backendDomain)
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
				Issuer:    iss,
				Audience:  []string{iss},
				Subject:   opts.Domain,
				IssuedAt:  iat,
				NotBefore: iat,
				ExpiresAt: exp,
				ID:        uuid.NewString(),
			},
		},
	)
}

type VerifyAccountCredentialsDynamicRegistrationTokenOptions struct {
	RequestID    string
	IAT          string
	GetPublicJWK GetPublicJWK
}

func (t *Tokens) VerifyAccountCredentialsDynamicRegistrationToken(
	ctx context.Context,
	opts VerifyAccountCredentialsDynamicRegistrationTokenOptions,
) (string, AccountClaims, error) {
	logger := utils.BuildLogger(t.logger, utils.LoggerOptions{
		Location:  dynamicRegistrationIATLocation,
		Method:    "VerifyAccountCredentialsDynamicRegistrationToken",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Verifying account credentials dynamic registration IAT...")

	claims := new(accountCredentialsDynamicRegistrationClaims)
	if _, err := jwt.ParseWithClaims(opts.IAT, claims, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			logger.DebugContext(ctx, "Failed to extract KID from account credentials dynamic registration IAT", "error", err)
			return nil, err
		}

		jwk, err := opts.GetPublicJWK(kid, utils.SupportedCryptoSuiteEd25519)
		if err != nil {
			logger.WarnContext(ctx, "Failed to get public JWK for account credentials dynamic registration IAT", "error", err, "kid", kid)
			return nil, err
		}

		return jwk.ToUsableKey()
	}); err != nil {
		logger.WarnContext(ctx, "Failed to verify account credentials dynamic registration IAT", "error", err)
		return "", AccountClaims{}, err
	}

	return claims.Domain, claims.AccountClaims, nil
}

func (t *Tokens) GetDynamicRegistrationTTL() int64 {
	return t.dynamicRegistrationTTL
}
