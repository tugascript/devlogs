// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	jwksLocation string = "jwks"

	maxRequestBodySize = 128 * 1024 // 128 KB
)

var client = &http.Client{
	Timeout: 10 * time.Second,
}

func httpGetWithinLimit(url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := http.MaxBytesReader(nil, resp.Body, maxRequestBodySize)
	return io.ReadAll(limited)
}

type PublicJWKsResult struct {
	Keys []utils.JWK `json:"keys"`
}

func (p *PublicJWKsResult) UnmarshalJSON(data []byte) error {
	type Alias PublicJWKsResult
	aux := &struct {
		Keys []json.RawMessage `json:"keys"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.Keys = make([]utils.JWK, 0, len(aux.Keys))
	for _, raw := range aux.Keys {
		jwk, err := utils.JsonToJWK(raw)
		if err != nil {
			return err
		}

		if jwk.GetKeyID() == "" {
			return errors.New("JWK is missing 'kid' field")
		}

		p.Keys = append(p.Keys, jwk)
	}

	return nil
}

type GetPublicJWKsOptions struct {
	RequestID string
	URL       string
}

func (t *Tokens) GetPublicJWKs(ctx context.Context, opts GetPublicJWKsOptions) (PublicJWKsResult, error) {
	logger := utils.BuildLogger(t.logger, utils.LoggerOptions{
		Location:  jwksLocation,
		Method:    "GetPublicJWKs",
		RequestID: opts.RequestID,
	})
	logger.DebugContext(ctx, "Fetching public JWKs")

	bytes, err := httpGetWithinLimit(opts.URL)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to fetch public JWKs", "error", err)
		return PublicJWKsResult{}, err
	}

	var result PublicJWKsResult
	if err := json.Unmarshal(bytes, &result); err != nil {
		logger.ErrorContext(ctx, "Failed to parse public JWKs", "error", err)
		return PublicJWKsResult{}, err
	}
	if len(result.Keys) == 0 {
		logger.ErrorContext(ctx, "No JWKs found in the response")
		return PublicJWKsResult{}, errors.New("no JWKs found in the response")
	}

	logger.InfoContext(ctx, "Successfully fetched public JWKs", "keyCount", len(result.Keys))
	return result, nil
}
