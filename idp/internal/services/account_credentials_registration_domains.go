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
	accountCredentialsRegistrationDomainsLocation string = "account_credentials_registration_domains"

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
) (dtos.DynamicRegistrationDomainDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "CreateAccountCredentialsRegistrationDomain").With(
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
			return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewNotFoundValidationError("Dynamic registration config not found")
		}
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}
	if len(dynamicRegistrationConfig.WhitelistedDomains) > 0 && !slices.Contains(dynamicRegistrationConfig.WhitelistedDomains, opts.Domain) {
		logger.WarnContext(ctx, "Domain is not whitelisted", "domain", opts.Domain)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewForbiddenValidationError("Domain is not whitelisted")
	}

	if _, err := s.database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomain(ctx, database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomainParams{
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Failed to find account dynamic registration domain", "error", err)
			return dtos.DynamicRegistrationDomainDTO{}, serviceErr
		}
	} else {
		logger.InfoContext(ctx, "Account dynamic registration domain already exists", "domain", opts.Domain)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewConflictError("Account credentials registration domain already exists")
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.FromDBError(err)
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
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	code, err := utils.GenerateBase64Secret(domainCodeByteLength)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate domain code", "error", err)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
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
			codeID, err := qrs.CreateDynamicRegistrationDomainCode(
				ctx,
				database.CreateDynamicRegistrationDomainCodeParams{
					AccountID:          accountDTO.ID(),
					VerificationCode:   hashedData,
					VerificationPrefix: verificationPrefix,
					VerificationHost:   s.accountDomainVerificationHost,
					HmacSecretID:       secretID,
					ExpiresAt:          exp,
				},
			)
			if err != nil {
				logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code", "error", err)
				return exceptions.FromDBError(err)
			}
			if err := qrs.CreateAccountDynamicRegistrationDomainCode(
				ctx,
				database.CreateAccountDynamicRegistrationDomainCodeParams{
					AccountDynamicRegistrationDomainID: domain.ID,
					DynamicRegistrationDomainCodeID:    codeID,
					AccountID:                          accountDTO.ID(),
				},
			); err != nil {
				logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code association", "error", err)
				return exceptions.FromDBError(err)
			}
			return nil
		},
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to hash code", "serviceError", serviceErr)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created account dynamic registration domain successfully")
	return dtos.MapAccountCredentialsRegistrationDomainToDTOWithCode(&domain, s.accountDomainVerificationHost, verificationPrefix, code, exp), nil
}

type GetAccountCredentialsRegistrationDomainOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Domain          string
}

func (s *Services) GetAccountCredentialsRegistrationDomain(
	ctx context.Context,
	opts GetAccountCredentialsRegistrationDomainOptions,
) (dtos.DynamicRegistrationDomainDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "GetAccountCredentialsRegistrationDomain").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Getting account credentials registration domain...")

	domainDTO, err := s.database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomain(ctx, database.FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomainParams{
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration domain", "error", err)
			return dtos.DynamicRegistrationDomainDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account dynamic registration domain not found", "domain", opts.Domain)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Found account dynamic registration domain", "domain", opts.Domain)
	return dtos.MapAccountCredentialsRegistrationDomainToDTO(&domainDTO), nil
}

type ListAccountCredentialsRegistrationDomainsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Offset          int32
	Limit           int32
	Order           string
}

func (s *Services) ListAccountCredentialsRegistrationDomains(
	ctx context.Context,
	opts ListAccountCredentialsRegistrationDomainsOptions,
) ([]dtos.DynamicRegistrationDomainDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "ListAccountCredentialsRegistrationDomains").With(
		"accountPublicID", opts.AccountPublicID,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Listing account credentials registration domains...")

	order := utils.Lowered(opts.Order)
	var domains []database.AccountDynamicRegistrationDomain
	var err error
	switch order {
	case "date":
		domains, err = s.database.FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByID(
			ctx,
			database.FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Limit:           opts.Limit,
				Offset:          opts.Offset,
			},
		)
	case "domain":
		domains, err = s.database.FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain(
			ctx,
			database.FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomainParams{
				AccountPublicID: opts.AccountPublicID,
				Limit:           opts.Limit,
				Offset:          opts.Offset,
			},
		)
	default:
		logger.WarnContext(ctx, "Invalid order parameter", "order", opts.Order)
		return nil, 0, exceptions.NewValidationError("Invalid order parameter")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to find account dynamic registration domains", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountAccountDynamicRegistrationDomainsByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account dynamic registration domains", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Listed account dynamic registration domains successfully")
	return utils.MapSlice(domains, dtos.MapAccountCredentialsRegistrationDomainToDTO), count, nil
}

type FilterAccountCredentialsRegistrationDomainsOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Search          string
	Offset          int32
	Limit           int32
	Order           string
}

func (s *Services) FilterAccountCredentialsRegistrationDomains(
	ctx context.Context,
	opts FilterAccountCredentialsRegistrationDomainsOptions,
) ([]dtos.DynamicRegistrationDomainDTO, int64, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "FilterAccountCredentialsRegistrationDomains").With(
		"accountPublicID", opts.AccountPublicID,
		"search", opts.Search,
		"offset", opts.Offset,
		"limit", opts.Limit,
		"order", opts.Order,
	)
	logger.InfoContext(ctx, "Filtering account credentials registration domains...")

	domainSearch := utils.DbSearch(opts.Search)
	order := utils.Lowered(opts.Order)
	var domains []database.AccountDynamicRegistrationDomain
	var err error

	switch order {
	case "date":
		domains, err = s.database.FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByID(
			ctx,
			database.FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByIDParams{
				AccountPublicID: opts.AccountPublicID,
				Domain:          domainSearch,
				Limit:           opts.Limit,
				Offset:          opts.Offset,
			},
		)
	case "domain":
		domains, err = s.database.FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain(
			ctx,
			database.FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomainParams{
				AccountPublicID: opts.AccountPublicID,
				Domain:          domainSearch,
				Limit:           opts.Limit,
				Offset:          opts.Offset,
			},
		)
	default:
		logger.WarnContext(ctx, "Invalid order parameter", "order", opts.Order)
		return nil, 0, exceptions.NewValidationError("Invalid order parameter")
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to filter account dynamic registration domains", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	count, err := s.database.CountFilteredAccountDynamicRegistrationDomainsByAccountPublicID(
		ctx,
		database.CountFilteredAccountDynamicRegistrationDomainsByAccountPublicIDParams{
			AccountPublicID: opts.AccountPublicID,
			Domain:          domainSearch,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count filtered account dynamic registration domains", "error", err)
		return nil, 0, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Filtered account dynamic registration domains successfully")
	return utils.MapSlice(domains, dtos.MapAccountCredentialsRegistrationDomainToDTO), count, nil
}

type DeleteAccountCredentialsRegistrationDomainOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
}

func (s *Services) DeleteAccountCredentialsRegistrationDomain(
	ctx context.Context,
	opts DeleteAccountCredentialsRegistrationDomainOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "DeleteAccountCredentialsRegistrationDomain").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Deleting account credentials registration domain...")

	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: "",
		PublicID:  uuid.UUID{},
		Version:   0,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return serviceErr
	}

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account credentials registration domain", "error", serviceErr)
		return serviceErr
	}
	if err := s.database.DeleteAccountDynamicRegistrationDomain(ctx, domainDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account dynamic registration domain", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Deleted account credentials registration domain")
	return nil
}

type VerifyAccountCredentialsRegistrationDomainOptions struct {
	RequestID        string
	AccountPublicID  uuid.UUID
	AccountVersion   int32
	Domain           string
	VerificationCode string
}

func (s *Services) VerifyAccountCredentialsRegistrationDomain(
	ctx context.Context,
	opts VerifyAccountCredentialsRegistrationDomainOptions,
) (dtos.DynamicRegistrationDomainDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "VerifyAccountCredentialsRegistrationDomain").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
		"verificationCode", opts.VerificationCode,
	)
	logger.InfoContext(ctx, "Verifying account credentials registration domain...")

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if serviceErr != nil {
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	if domainDTO.Verified {
		logger.InfoContext(ctx, "Account credentials registration domain already verified", "domain", opts.Domain)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewConflictError("Account credentials registration domain already verified")
	}

	if domainDTO.VerificationMethod != database.DomainVerificationMethodDnsTxtRecord {
		logger.WarnContext(ctx, "Invalid verification method", "verificationMethod", domainDTO.VerificationMethod)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewValidationError("Invalid verification method")
	}

	accountID, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	code, err := s.database.FindDynamicRegistrationDomainCodeByAccountDynamicRegistrationDomainID(ctx, domainDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration domain code", "error", err)
			return dtos.DynamicRegistrationDomainDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account dynamic registration domain code not found", "error", err)
		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewNotFoundValidationError("Account dynamic registration domain code not found")
	}

	if code.ExpiresAt.Before(time.Now()) {
		logger.WarnContext(ctx, "Account dynamic registration domain code expired", "expiresAt", code.ExpiresAt.Unix())
		if err := s.database.DeleteDynamicRegistrationDomainCode(ctx, code.ID); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account dynamic registration domain code", "error", err)
			return dtos.DynamicRegistrationDomainDTO{}, exceptions.FromDBError(err)
		}

		return dtos.DynamicRegistrationDomainDTO{}, exceptions.NewValidationError("Registration domain code expired, generate a new one")
	}

	if serviceErr := s.crypto.HMACSha256CompareHash(ctx, crypto.HMACSha256CompareHashOptions{
		RequestID: opts.RequestID,
		PlainText: code.VerificationCode,
		HashedSecretFN: func() (string, string, *exceptions.ServiceError) {
			return code.HmacSecretID, code.VerificationCode, nil
		},
		GetHMACSecretByIDFN: s.BuildGetHMACSecretByIDFN(ctx, BuildGetHMACSecretByIDFNOptions{
			RequestID: opts.RequestID,
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
		StoreReEncryptedHMACSecretFN: s.BuildUpdateHMACSecretFN(ctx, BuildUpdateHMACSecretFNOptions{
			RequestID: opts.RequestID,
			AccountID: accountID,
		}),
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to verify account credentials registration domain", "serviceError", serviceErr)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	if serviceErr := s.verifyTXTRecord(ctx, verifyTXTRecordOptions{
		requestID: opts.RequestID,
		host:      code.VerificationHost,
		domain:    opts.Domain,
		prefix:    code.VerificationPrefix,
		code:      opts.VerificationCode,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to verify TXT record", "serviceError", serviceErr)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	domain, err := qrs.VerifyAccountDynamicRegistrationDomain(
		ctx,
		database.VerifyAccountDynamicRegistrationDomainParams{
			ID:                 domainDTO.ID(),
			VerificationMethod: database.DomainVerificationMethodDnsTxtRecord,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify account dynamic registration domain", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}
	if err = qrs.DeleteDynamicRegistrationDomainCode(ctx, code.ID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account dynamic registration domain code", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.DynamicRegistrationDomainDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Verified account credentials registration domain successfully", "domain", opts.Domain)
	return dtos.MapAccountCredentialsRegistrationDomainToDTO(&domain), nil
}

type GetAccountCredentialsRegistrationDomainCodeOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	Domain          string
}

func (s *Services) GetAccountCredentialsRegistrationDomainCode(
	ctx context.Context,
	opts GetAccountCredentialsRegistrationDomainCodeOptions,
) (dtos.DynamicRegistrationDomainCodeDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "GetAccountCredentialsRegistrationDomainCode").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Getting account credentials registration domain code...")

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if serviceErr != nil {
		return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
	}

	if domainDTO.VerificationMethod != database.DomainVerificationMethodDnsTxtRecord {
		logger.WarnContext(ctx, "Invalid verification method", "verificationMethod", domainDTO.VerificationMethod)
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewValidationError("Invalid verification method")
	}
	if domainDTO.Verified {
		logger.InfoContext(ctx, "Verification code not available for verified domain")
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewConflictError("Verification code not available for verified domain")
	}

	code, err := s.database.FindDynamicRegistrationDomainCodeByAccountDynamicRegistrationDomainID(ctx, domainDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration domain code", "error", err)
			return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account dynamic registration domain code not found", "error", err)
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewNotFoundValidationError("Account dynamic registration domain code not found")
	}

	logger.InfoContext(ctx, "Found account dynamic registration domain code")
	return dtos.MapDynamicRegistrationDomainCodeToDTO(&code), nil
}

type SaveAccountCredentialsRegistrationDomainCodeOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
}

func (s *Services) SaveAccountCredentialsRegistrationDomainCode(
	ctx context.Context,
	opts SaveAccountCredentialsRegistrationDomainCodeOptions,
) (dtos.DynamicRegistrationDomainCodeDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "SaveAccountCredentialsRegistrationDomainCode").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Saving account credentials registration domain code...")

	domainDTO, serviceErr := s.GetAccountCredentialsRegistrationDomain(ctx, GetAccountCredentialsRegistrationDomainOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		Domain:          opts.Domain,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration domain code", "serviceError", serviceErr)
			return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account dynamic registration domain not found")
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewNotFoundValidationError("Account dynamic registration domain code not found")
	}

	if domainDTO.VerificationMethod != database.DomainVerificationMethodDnsTxtRecord {
		logger.WarnContext(ctx, "Invalid verification method", "verificationMethod", domainDTO.VerificationMethod)
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewValidationError("Invalid verification method")
	}
	if domainDTO.Verified {
		logger.InfoContext(ctx, "Verification code not available for verified domain")
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewConflictError("Verification code not available for verified domain")
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
	}

	verificationCode, err := utils.GenerateBase64Secret(domainCodeByteLength)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate domain code", "error", err)
		return dtos.DynamicRegistrationDomainCodeDTO{}, exceptions.NewInternalServerError()
	}

	verificationPrefix := fmt.Sprintf("%s-verification", accountDTO.Username)
	exp := time.Now().Add(s.accountDomainVerificationTTL)
	code, err := s.database.FindDynamicRegistrationDomainCodeByAccountDynamicRegistrationDomainID(ctx, domainDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account dynamic registration domain code", "error", err)
			return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
		}

		if serviceErr := s.crypto.HMACSha256Hash(ctx, crypto.HMACSha256HashOptions{
			RequestID: opts.RequestID,
			PlainText: verificationCode,
			GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
			}),
			GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
			}),
			GetHMACSecretFN: s.BuildGetHMACSecretFN(ctx, BuildGetHMACSecretFNOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
			}),
			StoreReEncryptedHMACSecretFN: s.BuildUpdateHMACSecretFN(ctx, BuildUpdateHMACSecretFNOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
			}),
			StoreHashedDataFN: func(secretID string, hashedData string) *exceptions.ServiceError {
				var serviceErr *exceptions.ServiceError
				qrs, txn, err := s.database.BeginTx(ctx)
				if err != nil {
					logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
					serviceErr = exceptions.FromDBError(err)
					return serviceErr
				}
				defer func() {
					logger.DebugContext(ctx, "Finalizing transaction")
					s.database.FinalizeTx(ctx, txn, err, serviceErr)
				}()

				codeID, err := qrs.CreateDynamicRegistrationDomainCode(
					ctx,
					database.CreateDynamicRegistrationDomainCodeParams{
						AccountID:          accountDTO.ID(),
						VerificationCode:   hashedData,
						VerificationPrefix: verificationPrefix,
						VerificationHost:   s.accountDomainVerificationHost,
						HmacSecretID:       secretID,
						ExpiresAt:          exp,
					},
				)
				if err != nil {
					logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code", "error", err)
					serviceErr = exceptions.FromDBError(err)
					return serviceErr
				}
				if err := qrs.CreateAccountDynamicRegistrationDomainCode(
					ctx,
					database.CreateAccountDynamicRegistrationDomainCodeParams{
						AccountDynamicRegistrationDomainID: domainDTO.ID(),
						DynamicRegistrationDomainCodeID:    codeID,
						AccountID:                          accountDTO.ID(),
					},
				); err != nil {
					logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code association", "error", err)
					serviceErr = exceptions.FromDBError(err)
					return serviceErr
				}
				return nil
			},
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to hash code", "serviceError", serviceErr)
			return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
		}

		return dtos.CreateDynamicRegistrationDomainCodeDTO(
			s.accountDomainVerificationHost,
			verificationPrefix,
			verificationCode,
			exp,
		), nil
	}

	if serviceErr := s.crypto.HMACSha256Hash(ctx, crypto.HMACSha256HashOptions{
		RequestID: opts.RequestID,
		PlainText: verificationCode,
		GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
		}),
		GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
		}),
		GetHMACSecretFN: s.BuildGetHMACSecretFN(ctx, BuildGetHMACSecretFNOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
		}),
		StoreReEncryptedHMACSecretFN: s.BuildUpdateHMACSecretFN(ctx, BuildUpdateHMACSecretFNOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
		}),
		StoreHashedDataFN: func(secretID string, hashedData string) *exceptions.ServiceError {
			if err := s.database.UpdateDynamicRegistrationDomainCode(
				ctx,
				database.UpdateDynamicRegistrationDomainCodeParams{
					ID:                 code.ID,
					VerificationCode:   hashedData,
					VerificationPrefix: verificationPrefix,
					VerificationHost:   s.accountDomainVerificationHost,
					HmacSecretID:       secretID,
					ExpiresAt:          exp,
				},
			); err != nil {
				logger.ErrorContext(ctx, "Failed to create account dynamic registration domain code", "error", err)
				serviceErr = exceptions.FromDBError(err)
				return serviceErr
			}
			return nil
		},
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to hash code", "serviceError", serviceErr)
		return dtos.DynamicRegistrationDomainCodeDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Saved account dynamic registration domain code successfully")
	return dtos.CreateDynamicRegistrationDomainCodeDTO(
		s.accountDomainVerificationHost,
		verificationPrefix,
		verificationCode,
		exp,
	), nil
}

type DeleteAccountCredentialsRegistrationDomainCodeOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	Domain          string
}

func (s *Services) DeleteAccountCredentialsRegistrationDomainCode(
	ctx context.Context,
	opts DeleteAccountCredentialsRegistrationDomainCodeOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountCredentialsRegistrationDomainsLocation, "DeleteAccountCredentialsRegistrationDomainCode").With(
		"accountPublicID", opts.AccountPublicID,
		"domain", opts.Domain,
	)
	logger.InfoContext(ctx, "Deleting account credentials registration domain...")

	domainCodeDTO, serviceErr := s.GetAccountCredentialsRegistrationDomainCode(
		ctx,
		GetAccountCredentialsRegistrationDomainCodeOptions{
			RequestID:       opts.RequestID,
			AccountPublicID: opts.AccountPublicID,
			Domain:          opts.Domain,
		},
	)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account credentials registration domain code", "serviceError", serviceErr)
		return serviceErr
	}
	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID", "serviceError", serviceErr)
		return serviceErr
	}

	if err := s.database.DeleteDynamicRegistrationDomainCode(ctx, domainCodeDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account dynamic registration domain", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Deleted account credentials registration domain successfully")
	return nil
}
