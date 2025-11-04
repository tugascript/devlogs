// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const appDynamicRegistrationIATLocation = "app_credentials_registration_iat"

type CreateAppCredentialsRegistrationIATOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
	BackendDomain   string
}

func (s *Services) CreateAppCredentialsRegistrationIAT(
	ctx context.Context,
	opts CreateAppCredentialsRegistrationIATOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationIATLocation, "CreateAppCredentialsRegistrationIAT").With(
		"accountPublicId", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Creating app credentials registration IAT...")

	if _, serviceErr := s.GetAppCredentialsRegistrationDomain(ctx, GetAppCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get app credentials registration domain", "serviceError", serviceErr)
		return "", serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "serviceError", serviceErr)
		return "", serviceErr
	}

	accountID := accountDTO.ID()
	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.DynamicRegistrationIAT(tokens.DynamicRegistrationIATOptions{
			AccountPublicID: opts.AccountPublicID,
			AccountVersion:  opts.AccountVersion,
			IssuerDomain:    fmt.Sprintf("%s.%s", accountDTO.Username, opts.BackendDomain),
			Domain:          opts.Domain,
			ClientID:        utils.Base62UUID(),
		}),
		GetJWKfn: s.BuildGetEncryptedAccountJWKFn(ctx, BuildGetEncryptedAccountJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeDynamicRegistration,
			AccountID: accountID,
		}),
		GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
			RequestID: opts.RequestID,
			AccountID: accountID,
		}),
		GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.RequestID,
			AccountID: accountID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.RequestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign app credentials registration IAT", "serviceError", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Created app credentials registration IAT successfully")
	return signedToken, nil
}

type ProcessAppCredentialsRegistrationIATAuthOptions struct {
	RequestID       string
	AuthHeader      string
	AccountUsername string
	AccountID       int32
	BackendDomain   string
}

func (s *Services) ProcessAppCredentialsRegistrationIATAuth(
	ctx context.Context,
	opts ProcessAppCredentialsRegistrationIATAuthOptions,
) (string, tokens.AccountClaims, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, appDynamicRegistrationIATLocation, "ProcessAppCredentialsRegistrationIATAuth")
	logger.InfoContext(ctx, "Processing app credentials registration IAT auth...")

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
			IssuerDomain: fmt.Sprintf("%s.%s", opts.AccountUsername, opts.BackendDomain),
			GetPublicJWK: s.buildVerifyAccountKeyFn(ctx, logger, buildVerifyAccountKeyFnOptions{
				requestID: opts.RequestID,
				accountID: opts.AccountID,
				keyType:   database.TokenKeyTypeDynamicRegistration,
			}),
		},
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify app credentials registration IAT", "error", err)
		return "", tokens.AccountClaims{}, exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Processed app credentials registration IAT auth successfully")
	return domain, accountClaims, nil
}
