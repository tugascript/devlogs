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
	"github.com/tugascript/devlogs/idp/internal/services/templates"
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

type InitiateAccountCredentialsRegistrationIATOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Domain          string
}

func (s *Services) InitiateAccountCredentialsRegistrationIAT(
	ctx context.Context,
	opts InitiateAccountCredentialsRegistrationIATOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationIATLocation, "InitiateAccountCredentialsRegistrationIAT").With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Initiating account credentials registration IAT generation...")

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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return "", serviceErr
	}

	authProviders, serviceErr := s.ListAccountAuthProviders(ctx, ListAccountAuthProvidersOptions{
		RequestID: opts.RequestID,
		PublicID:  accountDTO.PublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to list account auth providers", "serviceError", serviceErr)
		return "", serviceErr
	}

	clientID, err := s.cache.SaveAccountCredentialsDynamicRegistrationIAT(
		ctx,
		cache.SaveAccountCredentialsDynamicRegistrationIATOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: accountDTO.PublicID,
			Domain:          opts.Domain,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save account credentials dynamic registration IAT", "error", err)
		return "", exceptions.NewInternalServerError()
	}

	loginHTML, err := templates.BuildAccountDynamicRegistrationLoginTemplate(clientID, &accountDTO, authProviders)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build account dynamic registration login template", "error", err)
		return "", exceptions.NewInternalServerError()
	}
	return loginHTML, nil
}
