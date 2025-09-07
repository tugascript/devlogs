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

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const (
	account2FAConfigLocation = "account_2fa_configs"

	TwoFactorTypeEmail string = "email"
	TwoFactorTypeTotp  string = "totp"
)

type GetDefaultAccount2FAConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
}

func (s *Services) GetDefaultAccount2FAConfig(
	ctx context.Context,
	opts GetDefaultAccount2FAConfigOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "GetDefaultAccount2FAConfig").With(
		"accountPublicID", opts.AccountPublicID,
	)
	logger.InfoContext(ctx, "Getting default account 2FA config...")

	config, err := s.database.FindDefaultAccount2FAConfigByAccountPublicID(ctx, opts.AccountPublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Default account 2FA config not found", "error", err)
			return dtos.Account2FAConfigDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get default account 2FA config", "error", err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Default account 2FA config found")
	return dtos.MapAccount2FAConfigToDTO(&config), nil
}

type GetAccount2FAConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	TwoFAType       database.TwoFactorType
}

func (s *Services) GetAccount2FAConfig(
	ctx context.Context,
	opts GetAccount2FAConfigOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "GetAccount2FAConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"twoFAType", opts.TwoFAType,
	)
	logger.InfoContext(ctx, "Getting account 2FA config...")

	config, err := s.database.FindAccount2FAConfigByAccountPublicIDAndType(ctx, database.FindAccount2FAConfigByAccountPublicIDAndTypeParams{
		AccountPublicID: opts.AccountPublicID,
		TwoFactorType:   opts.TwoFAType,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account 2FA config not found", "error", err)
			return dtos.Account2FAConfigDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account 2FA config", "error", err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account 2FA config found")
	return dtos.MapAccount2FAConfigToDTO(&config), nil
}

type getDefaultAccount2FAConfigInternalOptions struct {
	requestID       string
	accountPublicID uuid.UUID
}

func (s *Services) getDefaultAccount2FAConfigInternal(
	ctx context.Context,
	opts getDefaultAccount2FAConfigInternalOptions,
) (*dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, account2FAConfigLocation, "getDefaultAccount2FAConfigInternal").With(
		"accountPublicID", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Getting default account 2FA config...")

	config, err := s.database.FindDefaultAccount2FAConfigByAccountPublicID(ctx, opts.accountPublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Default account 2FA config not found", "error", err)
			return nil, nil
		}

		logger.ErrorContext(ctx, "Failed to get default account 2FA config", "error", err)
		return nil, serviceErr
	}

	dto := dtos.MapAccount2FAConfigToDTO(&config)
	logger.InfoContext(ctx, "Default account 2FA config found")
	return &dto, nil
}

func Map2FAType(twoFAType string) (database.TwoFactorType, *exceptions.ServiceError) {
	switch twoFAType {
	case TwoFactorTypeEmail:
		return database.TwoFactorTypeEmail, nil
	case TwoFactorTypeTotp:
		return database.TwoFactorTypeTotp, nil
	default:
		return "", exceptions.NewValidationError("invalid two factor type")
	}
}

type buildStoreAccountTOTPOptions struct {
	requestID string
	accountID int32
	queries   *database.Queries
}

func (s *Services) buildStoreAccountTOTP(
	ctx context.Context,
	opts buildStoreAccountTOTPOptions,
) crypto.StoreTOTP {
	logger := s.buildLogger(opts.requestID, authLocation, "buildStoreAccountTOTP").With(
		"AccountID", opts.accountID,
	)
	logger.InfoContext(ctx, "Building store account TOTP function...")

	return func(dekKID, encSecret string, hashedCode []byte, url string) *exceptions.ServiceError {
		var serviceErr *exceptions.ServiceError

		qrs := s.mapQueries(opts.queries)
		id, err := qrs.CreateTotp(ctx, database.CreateTotpParams{
			DekKid:        dekKID,
			Url:           url,
			Secret:        encSecret,
			RecoveryCodes: hashedCode,
			Usage:         database.TotpUsageAccount,
			AccountID:     opts.accountID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to create TOTP", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}

		if err = qrs.CreateAccountTotp(ctx, database.CreateAccountTotpParams{
			AccountID: opts.accountID,
			TotpID:    id,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account recovery keys", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}

		return nil
	}
}

type createAccount2FAConfigInternalOptions struct {
	requestID     string
	isDefault     bool
	accountDTO    dtos.AccountDTO
	defaultConfig *dtos.Account2FAConfigDTO
}

func (s *Services) createTOTPAccount2FAConfig(
	ctx context.Context,
	opts createAccount2FAConfigInternalOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, account2FAConfigLocation, "createTOTPAccount2FAConfig").With(
		"accountID", opts.accountDTO.ID(),
		"isDefault", opts.isDefault,
	)
	logger.InfoContext(ctx, "Creating account 2FA config...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.Account2FAConfigDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	twoFAConfig, err := qrs.CreateAccount2FAConfig(ctx, database.CreateAccount2FAConfigParams{
		AccountID:       opts.accountDTO.ID(),
		AccountPublicID: opts.accountDTO.PublicID,
		TwoFactorType:   database.TwoFactorTypeTotp,
		IsDefault:       opts.isDefault || opts.defaultConfig == nil,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account 2FA config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	totpKey, err := s.crypto.GenerateTotpKey(ctx, crypto.GenerateTotpKeyOptions{
		RequestID: opts.requestID,
		Email:     opts.accountDTO.Email,
		GetDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.requestID,
			AccountID: opts.accountDTO.ID(),
			Queries:   qrs,
		}),
		StoreTOTPfn: s.buildStoreAccountTOTP(ctx, buildStoreAccountTOTPOptions{
			requestID: opts.requestID,
			accountID: opts.accountDTO.ID(),
			queries:   qrs,
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOTP", "error", err)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	if opts.defaultConfig != nil && opts.isDefault {
		if _, err := qrs.UpdateAccount2FAConfig(ctx, database.UpdateAccount2FAConfigParams{
			ID:        opts.defaultConfig.ID(),
			IsDefault: false,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update default account 2FA config", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.Account2FAConfigDTO{}, serviceErr
		}
	}

	account, err := qrs.UpdateAccountVersion(ctx, opts.accountDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account version", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version,
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyType2faAuthentication,
			TTL:       s.jwt.Get2FATTL(),
			Queries:   qrs,
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account 2FA config created successfully")
	return dtos.MapAccount2FAConfigTOTPToDTO(
		&twoFAConfig,
		signedToken,
		totpKey.Img(),
		totpKey.Codes(),
		s.jwt.Get2FATTL(),
		"Please scan QR Code with your authentication app",
	), nil
}

type createEmailAccount2FAConfigInternalOptions struct {
	requestID     string
	isDefault     bool
	accountDTO    dtos.AccountDTO
	defaultConfig *dtos.Account2FAConfigDTO
}

func (s *Services) createEmailAccount2FAConfig(
	ctx context.Context,
	opts createEmailAccount2FAConfigInternalOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, account2FAConfigLocation, "createEmailAccount2FAConfig").With(
		"accountID", opts.accountDTO.ID(),
		"isDefault", opts.isDefault,
	)
	logger.InfoContext(ctx, "Creating account 2FA config...")

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.Account2FAConfigDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	twoFAConfig, err := qrs.CreateAccount2FAConfig(ctx, database.CreateAccount2FAConfigParams{
		AccountID:       opts.accountDTO.ID(),
		AccountPublicID: opts.accountDTO.PublicID,
		TwoFactorType:   database.TwoFactorTypeEmail,
		IsDefault:       opts.isDefault || opts.defaultConfig == nil,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account 2FA config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	if opts.defaultConfig != nil && opts.isDefault {
		if _, err := qrs.UpdateAccount2FAConfig(ctx, database.UpdateAccount2FAConfigParams{
			ID:        opts.defaultConfig.ID(),
			IsDefault: false,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update default account 2FA config", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.Account2FAConfigDTO{}, serviceErr
		}
	}

	code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountDTO.ID(),
		TTL:       s.jwt.Get2FATTL(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate two factor Code", "error", err)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
		RequestID: opts.requestID,
		Email:     opts.accountDTO.Email,
		Name:      fmt.Sprintf("%s %s", opts.accountDTO.GivenName, opts.accountDTO.FamilyName),
		Code:      code,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
		serviceErr = exceptions.NewInternalServerError()
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	account, err := qrs.UpdateAccountVersion(ctx, opts.accountDTO.ID())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account version", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version,
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyType2faAuthentication,
			TTL:       s.jwt.Get2FATTL(),
			Queries:   qrs,
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.requestID,
			Queries:   qrs,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account 2FA config created successfully")
	return dtos.MapAccount2FAConfigCodeToDTO(
		&twoFAConfig,
		signedToken,
		s.jwt.Get2FATTL(),
		"Please enter the code sent to your email",
	), nil
}

type CreateAccount2FAConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	TwoFAType       string
	IsDefault       bool
}

func (s *Services) CreateAccount2FAConfig(
	ctx context.Context,
	opts CreateAccount2FAConfigOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "CreateAccount2FAConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"twoFAType", opts.TwoFAType,
		"isDefault", opts.IsDefault,
	)
	logger.InfoContext(ctx, "Creating account 2FA config...")

	twoFAType, serviceErr := Map2FAType(opts.TwoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	configDTO, serviceErr := s.getDefaultAccount2FAConfigInternal(ctx, getDefaultAccount2FAConfigInternalOptions{
		requestID:       opts.RequestID,
		accountPublicID: opts.AccountPublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get default account 2FA config", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	switch twoFAType {
	case database.TwoFactorTypeTotp:
		return s.createTOTPAccount2FAConfig(ctx, createAccount2FAConfigInternalOptions{
			requestID:     opts.RequestID,
			accountDTO:    accountDTO,
			isDefault:     opts.IsDefault,
			defaultConfig: configDTO,
		})
	case database.TwoFactorTypeEmail:
		return s.createEmailAccount2FAConfig(ctx, createEmailAccount2FAConfigInternalOptions{
			requestID:     opts.RequestID,
			accountDTO:    accountDTO,
			isDefault:     opts.IsDefault,
			defaultConfig: configDTO,
		})
	default:
		logger.WarnContext(ctx, "Invalid two factor type", "twoFAType", opts.TwoFAType)
		return dtos.Account2FAConfigDTO{}, exceptions.NewValidationError("invalid two factor type")
	}
}

type SetAccount2FAConfigDefaultOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	TwoFAType       string
}

func (s *Services) SetAccount2FAConfigDefault(
	ctx context.Context,
	opts SetAccount2FAConfigDefaultOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "SetAccount2FAConfigDefault").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"twoFAType", opts.TwoFAType,
	)
	logger.InfoContext(ctx, "Setting account 2FA config default...")

	twoFAType, serviceErr := Map2FAType(opts.TwoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	if _, serviceErr := s.GetAccountIDByPublicIDAndVersion(ctx, GetAccountIDByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	configDTO, serviceErr := s.GetAccount2FAConfig(ctx, GetAccount2FAConfigOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		TwoFAType:       twoFAType,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account 2FA config", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	if configDTO.IsDefault {
		logger.WarnContext(ctx, "Account 2FA config is already default", "twoFAType", opts.TwoFAType)
		return dtos.Account2FAConfigDTO{}, exceptions.NewForbiddenError()
	}

	defaultConfig, serviceErr := s.getDefaultAccount2FAConfigInternal(ctx, getDefaultAccount2FAConfigInternalOptions{
		requestID:       opts.RequestID,
		accountPublicID: opts.AccountPublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get default account 2FA config", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.Account2FAConfigDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	config, err := qrs.UpdateAccount2FAConfig(ctx, database.UpdateAccount2FAConfigParams{
		ID:        configDTO.ID(),
		IsDefault: true,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account 2FA config", "error", err)
		return dtos.Account2FAConfigDTO{}, exceptions.FromDBError(err)
	}

	if defaultConfig != nil {
		if _, err := qrs.UpdateAccount2FAConfig(ctx, database.UpdateAccount2FAConfigParams{
			ID:        defaultConfig.ID(),
			IsDefault: false,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update default account 2FA config", "error", err)
			return dtos.Account2FAConfigDTO{}, exceptions.FromDBError(err)
		}
	}

	logger.InfoContext(ctx, "Account 2FA config set as default successfully")
	return dtos.MapAccount2FAConfigToDTO(&config), nil
}

type DeleteAccount2FAConfigOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	TwoFAType       string
}

func (s *Services) DeleteAccount2FAConfig(
	ctx context.Context,
	opts DeleteAccount2FAConfigOptions,
) (dtos.Account2FAConfigDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "DeleteAccount2FAConfig").With(
		"accountPublicID", opts.AccountPublicID,
		"accountVersion", opts.AccountVersion,
		"twoFAType", opts.TwoFAType,
	)
	logger.InfoContext(ctx, "Deleting account 2FA config...")

	twoFAType, serviceErr := Map2FAType(opts.TwoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	config, err := s.database.FindAccount2FAConfigByAccountPublicIDAndType(ctx, database.FindAccount2FAConfigByAccountPublicIDAndTypeParams{
		AccountPublicID: opts.AccountPublicID,
		TwoFactorType:   twoFAType,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account 2FA config not found", "error", err)
			return dtos.Account2FAConfigDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account 2FA config", "error", err)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	code, err := s.cache.SaveDelete2FAConfigRequest(ctx, cache.SaveDelete2FAConfigRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.AccountPublicID,
		TwoFAType:  opts.TwoFAType,
		TTL:        s.jwt.Get2FATTL(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to save delete 2FA config request", "error", err)
		return dtos.Account2FAConfigDTO{}, exceptions.NewInternalServerError()
	}

	if opts.TwoFAType == "email" {
		if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
			RequestID: opts.RequestID,
			Email:     accountDTO.Email,
			Name:      fmt.Sprintf("%s %s", accountDTO.GivenName, accountDTO.FamilyName),
			Code:      code,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
			return dtos.Account2FAConfigDTO{}, exceptions.NewInternalServerError()
		}
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyType2faAuthentication,
			TTL:       s.jwt.Get2FATTL(),
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
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "serviceError", serviceErr)
		return dtos.Account2FAConfigDTO{}, serviceErr
	}

	msg := "Please enter the code sent to your email"
	if opts.TwoFAType == "totp" {
		msg = "Please enter the code from your authentication app"
	}

	return dtos.MapAccount2FAConfigCodeToDTO(
		&config,
		signedToken,
		s.jwt.Get2FATTL(),
		msg,
	), nil
}

type ConfirmDeleteAccount2FAConfigOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	TwoFAType string
	Code      string
}

func (s *Services) ConfirmDeleteAccount2FAConfig(
	ctx context.Context,
	opts ConfirmDeleteAccount2FAConfigOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, account2FAConfigLocation, "ConfirmDeleteAccount2FAConfig").With(
		"publicID", opts.PublicID,
		"version", opts.Version,
		"twoFAType", opts.TwoFAType,
		"code", opts.Code,
	)
	logger.InfoContext(ctx, "Confirming delete account 2FA config...")

	twoFAType, serviceErr := Map2FAType(opts.TwoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by public ID and version", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	ok, err := s.cache.VerifyDelete2FAConfigRequest(ctx, cache.VerifyDelete2FAConfigRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.PublicID,
		TwoFAType:  opts.TwoFAType,
		Code:       opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify delete 2FA config request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Delete 2FA config request does not match")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	configs, err := s.database.FindAccount2FAConfigsByAccountPublicID(ctx, accountDTO.PublicID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account 2FA configs", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	length := len(configs)
	if length == 0 {
		logger.WarnContext(ctx, "Account 2FA configs not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	if length == 1 {
		if err := qrs.DeleteAccount2FAConfig(ctx, configs[0].ID); err != nil {
			logger.ErrorContext(ctx, "Failed to delete account 2FA config", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		account, err := qrs.UpdateAccountVersion(ctx, accountDTO.ID())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to update account version", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		accountDTO = dtos.MapAccountToDTO(&account)
		return s.GenerateFullAuthDTO(
			ctx,
			logger,
			qrs,
			opts.RequestID,
			&accountDTO,
			[]tokens.AccountScope{tokens.AccountScopeAdmin},
			"Account 2FA config deleted successfully",
		)
	}

	idx := slices.IndexFunc(configs, func(config database.Account2faConfig) bool {
		return config.TwoFactorType == twoFAType
	})
	if idx == -1 {
		logger.WarnContext(ctx, "Account 2FA config not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	config := configs[idx]
	if err := qrs.DeleteAccount2FAConfig(ctx, config.ID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account 2FA config", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}
	if config.IsDefault {
		uIdx := 0
		if idx == 0 {
			uIdx = 1
		}

		if _, err := qrs.UpdateAccount2FAConfig(ctx, database.UpdateAccount2FAConfigParams{
			ID:        configs[uIdx].ID,
			IsDefault: true,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account 2FA config", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		qrs,
		opts.RequestID,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Account 2FA config deleted successfully",
	)
}
