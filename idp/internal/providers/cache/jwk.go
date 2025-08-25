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
	"strings"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	jwkLocation string = "jwk"

	jwkPrefix       string = "jwk"
	jwkPublicSuffix string = "public"
)

func buildJWKKey(prefix string, cryptoSuite utils.SupportedCryptoSuite, kid string) string {
	return fmt.Sprintf("%s:%s:%s:%s", jwkPrefix, prefix, cryptoSuite, kid)
}

type SavePublicJWKOptions struct {
	RequestID   string
	Prefix      string
	CryptoSuite utils.SupportedCryptoSuite
	KeyID       string
	PublicKey   []byte
}

func (c *Cache) SavePublicJWK(ctx context.Context, opts SavePublicJWKOptions) error {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "SavePublicJWK",
		RequestID: opts.RequestID,
	}).With(
		"kid", opts.KeyID,
	)
	logger.DebugContext(ctx, "Saving JWK...")

	key := buildJWKKey(opts.Prefix, opts.CryptoSuite, opts.KeyID)
	if err := c.storage.SetWithContext(ctx, key, opts.PublicKey, c.publicJWKTTL); err != nil {
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
	logger.DebugContext(ctx, "Getting JWK...")

	key := buildJWKKey(opts.Prefix, opts.CryptoSuite, opts.KeyID)
	val, err := c.storage.GetWithContext(ctx, key)
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

func encodeJWKPrivateKeyData(kid string, encPrivKey string) []byte {
	return fmt.Appendf(nil, "%s::%s", kid, encPrivKey)
}

func decodeJWKPrivateKeyData(data []byte) (string, string, error) {
	dataSlice := strings.Split(string(data), "::")
	if len(dataSlice) != 2 {
		return "", "", fmt.Errorf("invalid JWK private key data")
	}

	return dataSlice[0], dataSlice[1], nil
}

type SaveJWKPrivateKeyOptions struct {
	RequestID   string
	Suffix      string
	CryptoSuite utils.SupportedCryptoSuite
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

	if err := c.storage.SetWithContext(
		ctx,
		buildJWKPrivateKeyKey(opts.CryptoSuite, opts.Suffix),
		encodeJWKPrivateKeyData(opts.KID, opts.EncPrivKey),
		c.privateJWKTTL,
	); err != nil {
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
) (string, string, bool, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Location:  jwkLocation,
		Method:    "GetJWKPrivateKey",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Getting JWK private key...")

	key := buildJWKPrivateKeyKey(opts.CryptoSuite, opts.Suffix)
	val, err := c.storage.GetWithContext(ctx, key)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting JWK private key", "error", err)
		return "", "", false, err
	}
	if val == nil {
		logger.DebugContext(ctx, "JWK private key not found in cache")
		return "", "", false, nil
	}

	kid, encPrivKey, err := decodeJWKPrivateKeyData(val)
	if err != nil {
		logger.ErrorContext(ctx, "Error decoding JWK private key data", "error", err)
		return "", "", false, err
	}

	logger.DebugContext(ctx, "JWK private key found in cache", "kid", kid)
	return kid, encPrivKey, true, nil
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

	if err := c.storage.SetWithContext(
		ctx,
		fmt.Sprintf("%s:%s:%s", jwkPrefix, opts.Prefix, jwkPublicSuffix),
		jwksBytes,
		c.publicJWKsTTL,
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
	val, err := c.storage.GetWithContext(ctx, key)
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

	jwks := make([]utils.JWK, len(rawJwks))
	for i, raw := range rawJwks {
		jwks[i], err = utils.JsonToJWK(raw)
		if err != nil {
			logger.ErrorContext(ctx, "Error converting raw JWK to JWK", "error", err)
			return "", nil, false, err
		}
	}

	return utils.GenerateETag(val), jwks, true, nil
}
