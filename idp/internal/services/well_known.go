// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const wellKnownLocation = "well_known"

type WellKnownJWKsOptions struct {
	RequestID string
	AccountID int32
}

func (s *Services) WellKnownJWKs(
	ctx context.Context,
	opts WellKnownJWKsOptions,
) (string, dtos.JWKsDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, wellKnownLocation, "wellKnownJWKs").With(
		"AccountID", opts.AccountID,
	)
	logger.InfoContext(ctx, "Getting well known JWKs...")

	etag, jwks, serviceErr := s.GetAndCacheAccountDistributedJWK(ctx, GetAndCacheAccountDistributedJWKOptions(opts))
	if serviceErr != nil {
		return "", dtos.JWKsDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got well known JWKs successfully")
	return etag, dtos.NewJWKsDTO(jwks), nil
}

type WellKnownOIDCConfigurationWithCacheOptions struct {
	RequestID       string
	AccountID       int32
	BackendDomain   string
	AccountUsername string
}

func (s *Services) wellKnownOIDCConfiguration(
	ctx context.Context,
	opts WellKnownOIDCConfigurationWithCacheOptions,
) (dtos.WellKnownOIDCConfigurationDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, wellKnownLocation, "wellKnownOIDCConfiguration").With(
		"AccountID", opts.AccountID,
		"accountUsername", opts.AccountUsername,
	)
	logger.InfoContext(ctx, "Getting well known OIDC configuration...")

	configDTO, serviceErr := s.GetOrCreateOIDCConfig(ctx, GetOrCreateOIDCConfigOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
	})
	if serviceErr != nil {
		return dtos.WellKnownOIDCConfigurationDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got well known OIDC configuration successfully")
	return dtos.MapOIDCConfigDTOToWellKnownOIDCConfigurationDTO(&configDTO, opts.BackendDomain, opts.AccountUsername), nil
}

func (s *Services) WellKnownOIDCConfigurationWithCache(
	ctx context.Context,
	opts WellKnownOIDCConfigurationWithCacheOptions,
) (dtos.WellKnownOIDCConfigurationDTO, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, wellKnownLocation, "WellKnownOIDCConfiguration").With(
		"AccountID", opts.AccountID,
		"accountUsername", opts.AccountUsername,
	)
	logger.InfoContext(ctx, "Getting well known OIDC configuration with cache...")

	etag, configDTO, err := s.cache.GetWellKnownOIDCConfig(ctx, cache.GetWellKnownOIDCConfigOptions{
		RequestID:       opts.RequestID,
		AccountUsername: opts.AccountUsername,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error getting well known OIDC configuration from cache", "error", err)
		return dtos.WellKnownOIDCConfigurationDTO{}, "", exceptions.NewServerError()
	}
	if etag != "" && configDTO != nil {
		logger.InfoContext(ctx, "Got well known OIDC configuration from cache successfully")
		return *configDTO, etag, nil
	}

	wellKnownOIDCConfigDTO, serviceErr := s.wellKnownOIDCConfiguration(ctx, opts)
	if serviceErr != nil {
		return dtos.WellKnownOIDCConfigurationDTO{}, "", serviceErr
	}

	etag, err = s.cache.AddWellKnownOIDCConfig(ctx, cache.AddWellKnownOIDCConfigOptions{
		RequestID:       opts.RequestID,
		AccountUsername: opts.AccountUsername,
		OIDCConfig:      &wellKnownOIDCConfigDTO,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Error adding well known OIDC configuration to cache", "error", err)
		return dtos.WellKnownOIDCConfigurationDTO{}, "", exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Added well known OIDC configuration to cache successfully")
	return wellKnownOIDCConfigDTO, etag, nil
}
