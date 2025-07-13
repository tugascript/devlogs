// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	jwkLocation string        = "jwk"
	jwkPrefix   string        = "jwk"
	jwkDuration time.Duration = 1 * time.Hour

	jwkPublicSuffix   string        = "public"
	jwkPublicDuration time.Duration = 5 * time.Minute
)

func buildJWKKey(prefix string, cryptoSuite utils.SupportedCryptoSuite, kid string) string {
	return fmt.Sprintf("%s:%s:%s:%s", jwkPrefix, prefix, cryptoSuite, kid)
}

type SaveJWKOptions struct {
	RequestID   string
	Prefix      string
	CryptoSuite utils.SupportedCryptoSuite
	KeyID       string
	PublicKey   []byte
}

func (c *Cache) SaveJWK(ctx context.Context, opts SaveJWKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "SaveJWK",
		RequestID: opts.RequestID,
	}).With(
		"kid", opts.KeyID,
	)
	logger.DebugContext(ctx, "Saving JWK...")

	key := buildJWKKey(opts.Prefix, opts.CryptoSuite, opts.KeyID)
	if err := c.storage.Set(key, opts.PublicKey, jwkDuration); err != nil {
		logger.ErrorContext(ctx, "Error caching JWK", "error", err)
		return err
	}

	return nil
}

type GetJWKOptions struct {
	RequestID   string
	Prefix      string
	CryptoSuite utils.SupportedCryptoSuite
	KeyID       string
}

func (c *Cache) GetJWK(ctx context.Context, opts GetJWKOptions) (utils.JWK, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GetJWK",
		RequestID: opts.RequestID,
	}).With(
		"kid", opts.KeyID,
	)

	key := buildJWKKey(opts.Prefix, opts.CryptoSuite, opts.KeyID)
	val, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting JWK", "error", err)
		return nil, false, err
	}
	if val == nil {
		logger.DebugContext(ctx, "JWK not found in cache")
		return nil, false, nil
	}

	jwk, err := utils.JsonToJWK(val)
	if err != nil {
		logger.ErrorContext(ctx, "Error deserializing JWK", "error", err)
		return nil, false, err
	}

	return jwk, true, nil
}

func buildJWKPrivateKeyKey(cryptoSuite utils.SupportedCryptoSuite, suffix string) string {
	return fmt.Sprintf("%s:%s:%s", jwkPrefix, cryptoSuite, suffix)
}

type privateKetData struct {
	KID        string `json:"kid"`
	EncPrivKey string `json:"private_key"`
	DEKID      string `json:"dek_id"`
}

type SaveJWKPrivateKeyOptions struct {
	RequestID   string
	Suffix      string
	CryptoSuite utils.SupportedCryptoSuite
	DEKID       string
	KID         string
	EncPrivKey  string
}

func (c *Cache) SaveJWKPrivateKey(ctx context.Context, opts SaveJWKPrivateKeyOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "SaveJWKPrivateKey",
		RequestID: opts.RequestID,
	}).With("kid", opts.KID)
	logger.DebugContext(ctx, "Saving JWK private key...")

	data := privateKetData{
		KID:        opts.KID,
		EncPrivKey: opts.EncPrivKey,
		DEKID:      opts.DEKID,
	}
	json, err := json.Marshal(data)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling JWK private key", "error", err)
		return err
	}

	if err := c.storage.Set(buildJWKPrivateKeyKey(opts.CryptoSuite, opts.Suffix), json, jwkDuration); err != nil {
		logger.ErrorContext(ctx, "Error caching JWK private key", "error", err)
		return err
	}

	return nil
}

type GetJWKPrivateKeyOptions struct {
	RequestID   string
	Suffix      string
	CryptoSuite utils.SupportedCryptoSuite
}

func (c *Cache) GetJWKPrivateKey(
	ctx context.Context,
	opts GetJWKPrivateKeyOptions,
) (string, string, string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GetJWKPrivateKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting JWK private key...")

	key := buildJWKPrivateKeyKey(opts.CryptoSuite, opts.Suffix)
	val, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting JWK private key", "error", err)
		return "", "", "", false, err
	}
	if val == nil {
		logger.DebugContext(ctx, "JWK private key not found in cache")
		return "", "", "", false, nil
	}

	var data privateKetData
	if err := json.Unmarshal(val, &data); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling JWK private key", "error", err)
		return "", "", "", false, err
	}

	return data.KID, data.EncPrivKey, data.DEKID, true, nil
}

type SavePublicJWKsOptions struct {
	RequestID string
	Prefix    string
	JWKs      [][]byte
}

func (c *Cache) SavePublicJWKs(
	ctx context.Context,
	opts SavePublicJWKsOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "SavePublicJWKs",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Saving public JWKs...")

	jwksBytes, err := json.Marshal(opts.JWKs)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling public JWKs", "error", err)
		return "", err
	}

	if err := c.storage.Set(
		fmt.Sprintf("%s:%s:%s", jwkPrefix, opts.Prefix, jwkPublicSuffix),
		jwksBytes,
		jwkPublicDuration,
	); err != nil {
		logger.ErrorContext(ctx, "Error caching public JWKs", "error", err)
		return "", err
	}

	return utils.GenerateETag(jwksBytes), nil
}

type GetPublicJWKsOptions struct {
	RequestID string
	Prefix    string
}

func (c *Cache) GetPublicJWKs(
	ctx context.Context,
	opts GetPublicJWKsOptions,
) (string, []utils.JWK, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GetPublicJWKs",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting public JWKs...")

	key := fmt.Sprintf("%s:%s:%s", jwkPrefix, opts.Prefix, jwkPublicSuffix)
	val, err := c.storage.Get(key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting public JWKs", "error", err)
		return "", nil, false, err
	}
	if val == nil {
		logger.DebugContext(ctx, "Public JWKs not found in cache")
		return "", nil, false, nil
	}

	var rawJwks []json.RawMessage
	if err := json.Unmarshal(val, &rawJwks); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling public JWKs", "error", err)
		return "", nil, false, err
	}

	jwks, err := utils.MapSliceWithErr(rawJwks, func(raw *json.RawMessage) (utils.JWK, error) {
		return utils.JsonToJWK(*raw)
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error converting raw JWKs to JWKs", "error", err)
		return "", nil, false, err
	}

	return utils.GenerateETag(val), jwks, true, nil
}
