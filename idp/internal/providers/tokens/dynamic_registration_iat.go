// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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

type DynamicRegistrationIATOptions struct {
	AccountPublicID uuid.UUID
	AccountVersion  int32
	IssuerDomain    string
	Domain          string
	ClientID        string
}

func (t *Tokens) DynamicRegistrationIAT(
	opts DynamicRegistrationIATOptions,
) *jwt.Token {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.dynamicRegistrationTTL)))
	iss := fmt.Sprintf("https://%s", opts.IssuerDomain)
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

type VerifyDynamicRegistrationIATOptions struct {
	RequestID    string
	IAT          string
	IssuerDomain string
	GetPublicJWK GetPublicJWK
}

func (t *Tokens) VerifyDynamicRegistrationIAT(
	ctx context.Context,
	opts VerifyDynamicRegistrationIATOptions,
) (string, AccountClaims, error) {
	logger := utils.BuildLogger(t.logger, utils.LoggerOptions{
		Location:  dynamicRegistrationIATLocation,
		Method:    "VerifyDynamicRegistrationIAT",
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

	issDomain, err := url.Parse(claims.Issuer)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse issuer from account credentials dynamic registration IAT", "error", err, "issuer", claims.Issuer)
		return "", AccountClaims{}, err
	}
	if issDomain.Host != opts.IssuerDomain {
		logger.WarnContext(ctx, "Issuer domain mismatch in account credentials dynamic registration IAT", "expected", opts.IssuerDomain, "actual", issDomain.Host)
		return "", AccountClaims{}, errors.New("issuer domain mismatch")
	}

	if len(claims.Audience) == 0 {
		logger.WarnContext(ctx, "Missing audience in account credentials dynamic registration IAT")
		return "", AccountClaims{}, errors.New("missing audience")
	}

	audDomain, err := url.Parse(claims.Audience[0])
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse audience from account credentials dynamic registration IAT", "error", err, "audience", claims.Audience[0])
		return "", AccountClaims{}, err
	}
	if audDomain.Host != opts.IssuerDomain {
		logger.WarnContext(ctx, "Audience domain mismatch in account credentials dynamic registration IAT", "expected", opts.IssuerDomain, "actual", audDomain.Host)
		return "", AccountClaims{}, errors.New("audience domain mismatch")
	}

	logger.InfoContext(ctx, "Verified account credentials dynamic registration IAT successfully")
	return claims.Domain, claims.AccountClaims, nil
}

func (t *Tokens) GetDynamicRegistrationTTL() int64 {
	return t.dynamicRegistrationTTL
}
