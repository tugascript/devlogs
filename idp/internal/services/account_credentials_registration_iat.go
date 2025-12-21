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
	BackendDomain   string
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

	if _, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account credentials registration domain", "serviceError", serviceErr)
		return "", serviceErr
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
		Token: s.jwt.DynamicRegistrationIAT(tokens.DynamicRegistrationIATOptions{
			AccountPublicID: opts.AccountPublicID,
			AccountVersion:  opts.AccountVersion,
			IssuerDomain:    opts.BackendDomain,
			Domain:          opts.Domain,
			ClientID:        utils.Base62UUID(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeDynamicRegistration,
			TTL:       s.jwt.GetDynamicRegistrationTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.RequestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.RequestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.RequestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign account credentials registration IAT", "serviceError", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Created account credentials registration IAT successfully")
	return signedToken, nil
}

type ProcessAccountCredentialsRegistrationIATAuthOptions struct {
	RequestID    string
	AuthHeader   string
	IssuerDomain string
}

func (s *Services) ProcessAccountCredentialsRegistrationIATAuth(
	ctx context.Context,
	opts ProcessAccountCredentialsRegistrationIATAuthOptions,
) (string, tokens.AccountClaims, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationIATLocation, "ProcessAccountCredentialsRegistrationIATAuth")
	logger.InfoContext(ctx, "Processing account credentials registration IAT auth...")

	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to extract token from auth header", "serviceError", serviceErr)
		return "", tokens.AccountClaims{}, serviceErr
	}

	domain, accountClaims, err := s.jwt.VerifyDynamicRegistrationIAT(
		ctx,
		tokens.VerifyDynamicRegistrationIATOptions{
			RequestID:    opts.RequestID,
			IAT:          token,
			IssuerDomain: opts.IssuerDomain,
			GetPublicJWK: s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
				RequestID: opts.RequestID,
				KeyType:   database.TokenKeyTypeDynamicRegistration,
			}),
		},
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify account credentials registration IAT", "error", err)
		return "", tokens.AccountClaims{}, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Processed account credentials registration IAT auth successfully")
	return domain, accountClaims, nil
}
