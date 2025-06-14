// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const clientCredentialsLocation string = "client_credentials"

type clientCredentialsSecretOptions struct {
	requestID string
	accountID int32
	expiresIn time.Duration
	prefix    string
}

func (s *Services) clientCredentialsSecret(
	ctx context.Context,
	opts clientCredentialsSecretOptions,
) (database.CreateCredentialsSecretParams, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, clientCredentialsLocation, "clientCredentialsSecret").With(
		"accountID", opts.accountID,
		"prefix", opts.prefix,
	)
	logger.InfoContext(ctx, "Generating client credentials secret...")

	secretID, err := utils.PrefixedID(opts.prefix)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate secret id", "error", err)
		return database.CreateCredentialsSecretParams{}, "", exceptions.NewServerError()
	}

	secret, err := utils.GenerateBase64Secret(accountSecretBytes)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate secret", "error", err)
		return database.CreateCredentialsSecretParams{}, "", exceptions.NewServerError()
	}

	hashedSecret, err := utils.Argon2HashString(secret)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash secret", "error", err)
		return database.CreateCredentialsSecretParams{}, "", exceptions.NewServerError()
	}

	return database.CreateCredentialsSecretParams{
		AccountID:    opts.accountID,
		SecretID:     secretID,
		ClientSecret: hashedSecret,
		ExpiresAt:    time.Now().Add(opts.expiresIn),
	}, secret, nil
}

type clientCredentialsKeyOptions struct {
	requestID string
	accountID int32
	expiresIn time.Duration
}

func (s *Services) clientCredentialsKey(
	ctx context.Context,
	opts clientCredentialsKeyOptions,
) (database.CreateCredentialsKeyParams, utils.ES256JWK, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, clientCredentialsLocation, "clientCredentialsKey").With(
		"accountID", opts.accountID,
	)
	logger.InfoContext(ctx, "Generating client credentials key...")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate key pair", "error", err)
		return database.CreateCredentialsKeyParams{}, utils.ES256JWK{}, exceptions.NewServerError()
	}

	pub := priv.Public().(*ecdsa.PublicKey)
	kid := utils.ExtractECDSAKeyID(pub)
	dbJwk := utils.EncodeP256Jwk(pub, kid)

	jsonJwk, err := json.Marshal(dbJwk)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal jwk", "error", err)
		return database.CreateCredentialsKeyParams{}, utils.ES256JWK{}, exceptions.NewServerError()
	}

	return database.CreateCredentialsKeyParams{
		AccountID: opts.accountID,
		PublicKid: kid,
		PublicKey: jsonJwk,
		ExpiresAt: time.Now().Add(opts.expiresIn),
	}, utils.EncodeP256JwkPrivate(priv, kid), nil
}

func isMoreThanHalfExpiry(createdAt, expiresAt time.Time) bool {
	now := time.Now()
	if now.Before(createdAt) || now.After(expiresAt) {
		return false
	}

	totalDuration := expiresAt.Sub(createdAt)
	halfDuration := totalDuration / 2
	elapsedDuration := now.Sub(createdAt)
	return elapsedDuration >= halfDuration
}
