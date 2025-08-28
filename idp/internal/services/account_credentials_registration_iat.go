// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const accountCredentialsRegistrationIATLocation = "account_credentials_registration_iat"

type CreateAccountCredentialsRegistrationIATOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
}

func (s *Services) CreateAccountCredentialsRegistrationIAT(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationIATOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationIATLocation, "CreateAccountCredentialsRegistrationIAT").With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Creating account credentials registration IAT...")

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
		return "", serviceErr
	}
	if !domainDTO.Verified {
		logger.ErrorContext(ctx, "Account credentials registration domain is not verified")
		return "", exceptions.NewValidationError("account credentials registration domain is not verified")
	}

	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return "", serviceErr
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.CreateAccountCredentialsDynamicRegistrationToken(tokens.AccountCredentialsDynamicRegistrationTokenOptions{
			AccountPublicID: opts.AccountPublicID,
			AccountVersion:  opts.AccountVersion,
			Domain:          opts.Domain,
			ClientID:        utils.Base62UUID(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeDynamicRegistration,
			TTL:       s.jwt.GetDynamicRegistrationTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, opts.RequestID),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, opts.RequestID),
		StoreFN:         s.BuildUpdateJWKDEKFn(ctx, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign account credentials registration IAT", "serviceError", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Created account credentials registration IAT successfully")
	return signedToken, nil
}

type VerifyAccountCredentialsRegistrationIATCodeOptions struct {
	RequestID    string
	Code         string
	CodeVerifier string
}

func (s *Services) VerifyAccountCredentialsRegistrationIATCode(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationIATCodeOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationIATLocation, "VerifyAccountCredentialsRegistrationIATCode")
	logger.InfoContext(ctx, "Verifying account credentials registration IAT code...")

	data, found, err := s.cache.VerifyAccountCredentialsRegistrationIATCode(ctx, cache.VerifyAccountCredentialsRegistrationIATCodeOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account credentials registration IAT code", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !found {
		logger.DebugContext(ctx, "Account credentials registration IAT code not found or invalid")
		return "", exceptions.NewUnauthorizedError()
	}

	ok, err := utils.CompareShaBase64(data.Challenge, opts.CodeVerifier)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare challenge", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth Code challenge verification failed")
		return "", exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountPublicID,
		Version:   data.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return "", serviceErr
	}

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		Domain:          data.Domain,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
		return "", serviceErr
	}
	if !domainDTO.Verified {
		logger.ErrorContext(ctx, "Account credentials registration domain is not verified")
		return "", exceptions.NewValidationError("account credentials registration domain is not verified")
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.CreateAccountCredentialsDynamicRegistrationToken(tokens.AccountCredentialsDynamicRegistrationTokenOptions{
			AccountPublicID: accountDTO.PublicID,
			AccountVersion:  accountDTO.Version(),
			Domain:          data.Domain,
			ClientID:        data.ClientID,
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeDynamicRegistration,
			TTL:       s.jwt.GetDynamicRegistrationTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, opts.RequestID),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, opts.RequestID),
		StoreFN:         s.BuildUpdateJWKDEKFn(ctx, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign account credentials registration IAT", "serviceError", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Verified account credentials registration IAT code successfully")
	return signedToken, nil
}
