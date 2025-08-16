// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	accountCredentialsRegistrationDomainLocation string = "account_credentials_registration_domain"

	domainCodeByteLength int = 32
)

type CreateAccountCredentialsRegistrationDomainOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
}

func (s *Services) CreateAccountCredentialsRegistrationDomain(
	ctx context.Context,
	opts CreateAccountCredentialsRegistrationDomainOptions,
) (dtos.AccountCredentialsRegistrationDomainDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainLocation, "CreateAccountCredentialsRegistrationDomain").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Creating account credentials registration domain...")

	dynamicRegistrationConfig, serviceErr := s.GetAccountDynamicRegistrationConfig(ctx, GetAccountDynamicRegistrationConfigOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account dynamic registration config not found", "serviceError", serviceErr)
			return dtos.AccountCredentialsRegistrationDomainDTO{}, exceptions.NewNotFoundValidationError("Dynamic registration config not found")
		}
		return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
	}
	if len(dynamicRegistrationConfig.WhitelistedDomains) > 0 && !slices.Contains(dynamicRegistrationConfig.WhitelistedDomains, opts.Domain) {
		logger.WarnContext(ctx, "Domain is not whitelisted", "domain", opts.Domain)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, exceptions.NewForbiddenValidationError("Domain is not whitelisted")
	}

	if _, err := s.database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomain(ctx, database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomainParams{
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Failed to find account dynamic registration domain", "error", err)
			return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
		}
	} else {
		logger.InfoContext(ctx, "Account dynamic registration domain already exists", "domain", opts.Domain)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, exceptions.NewConflictError("Account credentials registration domain already exists")
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	domain, err := qrs.CreateAccountDynamicRegistrationDomain(ctx, database.CreateAccountDynamicRegistrationDomainParams{
		AccountID:          accountDTO.ID(),
		AccountPublicID:    opts.AccountPublicID,
		Domain:             opts.Domain,
		VerificationMethod: database.DomainVerificationMethodDnsTxtRecord,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account dynamic registration domain", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
	}

	code, err := utils.GenerateBase64Secret(domainCodeByteLength)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate domain code", "error", err)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
	}

	verificationPrefix := fmt.Sprintf("%s-verification", accountDTO.Username)
	exp := time.Now().Add(s.accountDomainVerificationTTL)
	if serviceErr = s.crypto.HMACSha256Hash(ctx, crypto.HMACSha256HashOptions{
		RequestID: opts.RequestID,
		PlainText: code,
		GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Queries:   qrs,
		}),
		GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Queries:   qrs,
		}),
		GetHMACSecretFN: s.BuildGetHMACSecretFN(ctx, BuildGetHMACSecretFNOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Queries:   qrs,
		}),
		StoreReEncryptedHMACSecretFN: s.BuildUpdateHMACSecretFN(ctx, BuildUpdateHMACSecretFNOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Queries:   qrs,
		}),
		StoreHashedDataFN: func(secretID string, hashedData string) *exceptions.ServiceError {
			if err := qrs.CreateAccountDynamicRegistrationDomainCode(ctx, database.CreateAccountDynamicRegistrationDomainCodeParams{
				AccountID:                          accountDTO.ID(),
				AccountDynamicRegistrationDomainID: domain.ID,
				VerificationCode:                   hashedData,
				VerificationPrefix:                 verificationPrefix,
				VerificationHost:                   s.accountDomainVerificationHost,
				HmacSecretID:                       secretID,
				ExpiresAt:                          exp,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code", "error", err)
				return exceptions.FromDBError(err)
			}
			return nil
		},
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to hash code", "serviceError", serviceErr)
		return dtos.AccountCredentialsRegistrationDomainDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created account dynamic registration domain successfully")
	return dtos.MapAccountCredentialsRegistrationDomainToDTOWithCode(&domain, s.accountDomainVerificationHost, verificationPrefix, code, exp), nil
}
