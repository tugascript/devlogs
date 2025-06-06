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

	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	wellKnownLocation string = "well_known"

	wellKnownJWKsPrefix string = "well_known_jwks"
	wellKnownJWKsTTL    int    = 300

	wellKnownOIDCConfigPrefix string = "well_known_oidc_config"
	wellKnownOIDCConfigTTL    int    = 3600
)

type AddWellKnownJWKsOptions struct {
	RequestID       string
	AccountUsername string
	JWKs            *dtos.JWKsDTO
}

func (c *Cache) AddWellKnownJWKs(
	ctx context.Context,
	opts AddWellKnownJWKsOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  wellKnownLocation,
		Method:    "AddWellKnownJWKs",
		RequestID: opts.RequestID,
	}).With("accountUsername", opts.AccountUsername)
	logger.DebugContext(ctx, "Adding well known JWKs...")

	jwksBytes, err := json.Marshal(opts.JWKs)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling well known JWKs", "error", err)
		return "", err
	}

	if err := c.storage.Set(
		fmt.Sprintf("%s:%s", wellKnownJWKsPrefix, opts.AccountUsername),
		jwksBytes,
		time.Duration(wellKnownJWKsTTL)*time.Second,
	); err != nil {
		logger.ErrorContext(ctx, "Error adding well known JWKs", "error", err)
		return "", err
	}

	return utils.GenerateETag(jwksBytes), nil
}

type GetWellKnownJWKsOptions struct {
	RequestID       string
	AccountUsername string
}

func (c *Cache) GetWellKnownJWKs(
	ctx context.Context,
	opts GetWellKnownJWKsOptions,
) (string, *dtos.JWKsDTO, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  wellKnownLocation,
		Method:    "GetWellKnownJWKs",
		RequestID: opts.RequestID,
	}).With("accountUsername", opts.AccountUsername)
	logger.DebugContext(ctx, "Getting well known JWKs...")

	jwksBytes, err := c.storage.Get(
		fmt.Sprintf("%s:%s", wellKnownJWKsPrefix, opts.AccountUsername),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting well known JWKs", "error", err)
		return "", nil, err
	}
	if jwksBytes == nil {
		logger.DebugContext(ctx, "No well known JWKs found")
		return "", nil, nil
	}

	var jwksDTO dtos.JWKsDTO
	if err := json.Unmarshal(jwksBytes, &jwksDTO); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling well known JWKs", "error", err)
		return "", nil, err
	}

	return utils.GenerateETag(jwksBytes), &jwksDTO, nil
}

type AddWellKnownOIDCConfigOptions struct {
	RequestID       string
	AccountUsername string
	OIDCConfig      *dtos.WellKnownOIDCConfigurationDTO
}

func (c *Cache) AddWellKnownOIDCConfig(
	ctx context.Context,
	opts AddWellKnownOIDCConfigOptions,
) (string, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  wellKnownLocation,
		Method:    "AddWellKnownOIDCConfig",
		RequestID: opts.RequestID,
	}).With("accountUsername", opts.AccountUsername)
	logger.DebugContext(ctx, "Adding well known OIDC config...")

	oidcConfigBytes, err := json.Marshal(opts.OIDCConfig)
	if err != nil {
		logger.ErrorContext(ctx, "Error marshalling well known OIDC config", "error", err)
		return "", err
	}

	if err := c.storage.Set(
		fmt.Sprintf("%s:%s", wellKnownOIDCConfigPrefix, opts.AccountUsername),
		oidcConfigBytes,
		time.Duration(wellKnownOIDCConfigTTL)*time.Second,
	); err != nil {
		logger.ErrorContext(ctx, "Error adding well known OIDC config", "error", err)
		return "", err
	}

	return utils.GenerateETag(oidcConfigBytes), nil
}

type GetWellKnownOIDCConfigOptions struct {
	RequestID       string
	AccountUsername string
}

func (c *Cache) GetWellKnownOIDCConfig(
	ctx context.Context,
	opts GetWellKnownOIDCConfigOptions,
) (string, *dtos.WellKnownOIDCConfigurationDTO, error) {
	logger := utils.BuildLogger(c.logger, utils.LoggerOptions{
		Layer:     logLayer,
		Location:  wellKnownLocation,
		Method:    "GetWellKnownOIDCConfig",
		RequestID: opts.RequestID,
	}).With("accountUsername", opts.AccountUsername)
	logger.DebugContext(ctx, "Getting well known OIDC config...")

	oidcConfigBytes, err := c.storage.Get(
		fmt.Sprintf("%s:%s", wellKnownOIDCConfigPrefix, opts.AccountUsername),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Error getting well known OIDC config", "error", err)
		return "", nil, err
	}
	if oidcConfigBytes == nil {
		logger.DebugContext(ctx, "No well known OIDC config found")
		return "", nil, nil
	}

	var oidcConfigDTO dtos.WellKnownOIDCConfigurationDTO
	if err := json.Unmarshal(oidcConfigBytes, &oidcConfigDTO); err != nil {
		logger.ErrorContext(ctx, "Error unmarshalling well known OIDC config", "error", err)
		return "", nil, err
	}

	return utils.GenerateETag(oidcConfigBytes), &oidcConfigDTO, nil
}
