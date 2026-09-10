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
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const dynamicRegistrationIATLocation = "dynamic_registration_iat"

const registrationAccessTokenTTLSeconds int64 = 10 * 365 * 24 * 60 * 60

type DynamicRegistrationUsage string

const (
	DynamicRegistrationUsageAccount DynamicRegistrationUsage = "account"
	DynamicRegistrationUsageApp     DynamicRegistrationUsage = "app"
)

type DynamicRegistrationTokenUse string

const (
	DynamicRegistrationTokenUseInitialAccess DynamicRegistrationTokenUse = "initial_access"
	DynamicRegistrationTokenUseRegistration  DynamicRegistrationTokenUse = "registration"
)

type dynamicRegistrationTokenClaims struct {
	AccountClaims
	Usage    DynamicRegistrationUsage    `json:"usage"`
	TokenUse DynamicRegistrationTokenUse `json:"token_use"`
	jwt.RegisteredClaims
}

type DynamicRegistrationIATOptions struct {
	AccountPublicID uuid.UUID
	AccountVersion  int32
	IssuerDomain    string
	Subject         string
	JTI             string
	Usage           DynamicRegistrationUsage
	TokenUse        DynamicRegistrationTokenUse
	TTL             int64
}

func (t *Tokens) DynamicRegistrationIAT(
	opts DynamicRegistrationIATOptions,
) *jwt.Token {
	if opts.TokenUse == "" {
		opts.TokenUse = DynamicRegistrationTokenUseInitialAccess
	}
	if opts.TTL == 0 {
		opts.TTL = t.dynamicRegistrationTTL
	}
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.TTL)))
	iss := fmt.Sprintf("https://%s", opts.IssuerDomain)
	return jwt.NewWithClaims(
		jwt.SigningMethodEdDSA,
		dynamicRegistrationTokenClaims{
			AccountClaims: AccountClaims{
				AccountID:      opts.AccountPublicID,
				AccountVersion: opts.AccountVersion,
			},
			Usage:    opts.Usage,
			TokenUse: opts.TokenUse,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    iss,
				Audience:  []string{iss},
				Subject:   opts.Subject,
				IssuedAt:  iat,
				NotBefore: iat,
				ExpiresAt: exp,
				ID:        opts.JTI,
			},
		},
	)
}

func (t *Tokens) DynamicRegistrationAccessToken(opts DynamicRegistrationIATOptions) *jwt.Token {
	opts.TokenUse = DynamicRegistrationTokenUseRegistration
	if opts.TTL == 0 {
		opts.TTL = registrationAccessTokenTTLSeconds
	}
	return t.DynamicRegistrationIAT(opts)
}

type VerifyDynamicRegistrationIATOptions struct {
	RequestID    string
	IAT          string
	IssuerDomain string
	Usage        DynamicRegistrationUsage
	TokenUse     DynamicRegistrationTokenUse
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
	logger.DebugContext(ctx, "Verifying dynamic registration token...")

	if opts.TokenUse == "" {
		opts.TokenUse = DynamicRegistrationTokenUseInitialAccess
	}

	claims := new(dynamicRegistrationTokenClaims)
	if _, err := jwt.ParseWithClaims(opts.IAT, claims, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			logger.DebugContext(ctx, "Failed to extract KID from dynamic registration token", "error", err)
			return nil, err
		}

		jwk, err := opts.GetPublicJWK(kid, utils.SupportedCryptoSuiteEd25519)
		if err != nil {
			logger.WarnContext(ctx, "Failed to get public JWK for dynamic registration token", "error", err, "kid", kid)
			return nil, err
		}

		return jwk.ToUsableKey()
	}, jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer("https://"+opts.IssuerDomain),
		jwt.WithAudience("https://"+opts.IssuerDomain),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt()); err != nil {
		logger.WarnContext(ctx, "Failed to verify dynamic registration token", "error", err)
		return "", AccountClaims{}, err
	}

	if claims.Subject == "" || claims.ID == "" || claims.AccountID == uuid.Nil {
		return "", AccountClaims{}, errors.New("missing registration token binding")
	}
	if claims.Usage != opts.Usage {
		return "", AccountClaims{}, errors.New("registration token usage mismatch")
	}
	if claims.TokenUse != opts.TokenUse {
		return "", AccountClaims{}, errors.New("registration token use mismatch")
	}

	logger.InfoContext(ctx, "Verified dynamic registration token successfully")
	return claims.Subject, claims.AccountClaims, nil
}

func (t *Tokens) GetDynamicRegistrationTTL() int64 {
	return t.dynamicRegistrationTTL
}

func (t *Tokens) GetRegistrationAccessTokenTTL() int64 {
	return registrationAccessTokenTTLSeconds
}
