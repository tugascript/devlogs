// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const accountsLocation = "accounts"

type CreateAccountOptions struct {
	RequestID  string
	GivenName  string
	FamilyName string
	Email      string
	Password   string
	Provider   string
}

func (s *Services) CreateAccount(
	ctx context.Context,
	opts CreateAccountOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "CreateAccount").With(
		"givenName", opts.GivenName,
		"familyName", opts.FamilyName,
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Creating account...")

	authProvider, serviceErr := mapAuthProvider(opts.Provider)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to map auth provider", "serviceError", serviceErr)
		return dtos.AccountDTO{}, serviceErr
	}

	var email string
	var password pgtype.Text
	switch authProvider {
	case database.AuthProviderUsernamePassword:
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth Provider")
			return dtos.AccountDTO{}, exceptions.NewValidationError("password is required")
		}

		hashedPassword, err := utils.HashString(opts.Password)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to hash password", "error", err)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		if err := password.Scan(hashedPassword); err != nil {
			logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		email = utils.Lowered(opts.Email)
	case database.AuthProviderApple, database.AuthProviderGithub,
		database.AuthProviderGoogle, database.AuthProviderMicrosoft:
		email = utils.Lowered(opts.Email)
	case database.AuthProviderCustom:
		logger.WarnContext(ctx, "Custom auth provider not supported")
		return dtos.AccountDTO{}, exceptions.NewValidationError("custom auth provider not supported for account creation")
	default:
		logger.ErrorContext(ctx, "Provider must be 'email', 'apple', 'facebook', 'github', 'google' or 'microsoft'")
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}
	if _, err := s.database.FindAccountByEmail(ctx, email); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account by email", "error", serviceErr)
			return dtos.AccountDTO{}, serviceErr
		}
	} else {
		logger.WarnContext(ctx, "Account already exists for given email")
		return dtos.AccountDTO{}, exceptions.NewConflictError("Email already in use")
	}

	dek, err := s.encrypt.GenerateAccountDEK(ctx, opts.RequestID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate account DEK", "error", err)
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	publicID, err := uuid.NewRandom()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate public ID", "error", err)
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}

	givenName := utils.Capitalized(opts.GivenName)
	familyName := utils.Capitalized(opts.FamilyName)
	username := uuid.NewString()
	var account database.Account
	if authProvider == database.AuthProviderUsernamePassword {
		account, err = qrs.CreateAccountWithPassword(ctx, database.CreateAccountWithPasswordParams{
			PublicID:   publicID,
			GivenName:  givenName,
			FamilyName: familyName,
			Username:   username,
			Email:      email,
			Password:   password,
			Dek:        dek,
		})
	} else {
		account, err = qrs.CreateAccountWithoutPassword(ctx, database.CreateAccountWithoutPasswordParams{
			PublicID:   publicID,
			GivenName:  givenName,
			FamilyName: familyName,
			Username:   username,
			Email:      email,
			Dek:        dek,
		})
	}
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create account", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountDTO{}, serviceErr
	}

	if err := qrs.CreateAccountAuthProvider(ctx, database.CreateAccountAuthProviderParams{
		Email:    email,
		Provider: authProvider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create auth Provider", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Created account successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByEmailOptions struct {
	RequestID string
	Email     string
}

func (s *Services) GetAccountByEmail(
	ctx context.Context,
	opts GetAccountByEmailOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByEmail")
	logger.InfoContext(ctx, "Getting account by email...")

	account, err := s.database.FindAccountByEmail(ctx, utils.Lowered(opts.Email))
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by email successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByIDOptions struct {
	RequestID string
	ID        int32
}

func (s *Services) GetAccountByID(
	ctx context.Context,
	opts GetAccountByIDOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByID").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Getting account by AccountID...")

	account, err := s.database.FindAccountById(ctx, opts.ID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by AccountID successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByPublicIDOptions struct {
	RequestID string
	PublicID  uuid.UUID
}

func (s *Services) GetAccountByPublicID(
	ctx context.Context,
	opts GetAccountByPublicIDOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByPublicID").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Getting account by PublicID...")

	account, err := s.database.FindAccountByPublicID(ctx, opts.PublicID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by AccountID successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type GetAccountByPublicIDAndVersionOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
}

func (s *Services) GetAccountByPublicIDAndVersion(
	ctx context.Context,
	opts GetAccountByPublicIDAndVersionOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountByPublicIDAndVersion").With(
		"publicID", opts.PublicID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Getting account by PublicID and Version...")

	account, err := s.database.FindAccountByPublicIDAndVersion(ctx, database.FindAccountByPublicIDAndVersionParams{
		PublicID: opts.PublicID,
		Version:  opts.Version,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "error", err)
			return dtos.AccountDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", err)
		return dtos.AccountDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Got account by PublicID and Version successfully")
	return dtos.MapAccountToDTO(&account), nil
}

func (s *Services) updateAccountEmailInDB(
	ctx context.Context,
	logger *slog.Logger,
	accountID int32,
	oldEmail string,
	newEmail string,
) (database.Account, error) {
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return database.Account{}, err
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, nil)
	}()

	// Delete external auth providers since they won't be valid anymore
	err = qrs.DeleteExternalAccountAuthProviders(ctx, oldEmail)
	if err != nil {
		return database.Account{}, err
	}

	// Update account email
	account, err := qrs.UpdateAccountEmail(ctx, database.UpdateAccountEmailParams{
		ID:    accountID,
		Email: newEmail,
	})
	if err != nil {
		return database.Account{}, err
	}

	return account, nil
}

type UpdateAccountEmailOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Email     string
	Password  string
}

func (s *Services) UpdateAccountEmail(
	ctx context.Context,
	opts UpdateAccountEmailOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountEmail").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Updating account email...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	_, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: database.AuthProviderUsernamePassword,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Email auth Provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get email auth Provider", "error", err)
		return dtos.AuthDTO{}, serviceErr
	}

	ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare password hash", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Invalid password provided")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	newEmail := utils.Lowered(opts.Email)
	if accountDTO.TwoFactorType != database.TwoFactorTypeNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdateEmailRequest(ctx, cache.SaveUpdateEmailRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.SensitiveRequestAccountPrefix,
			PublicID:        accountDTO.PublicID,
			Email:           newEmail,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to cache email update request", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code to confirm email update",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Email update request cached successfully")
		return authDTO, serviceErr
	}

	if _, err := s.database.FindAccountByEmail(ctx, newEmail); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to check if email exists", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		logger.WarnContext(ctx, "Email already in use")
		return dtos.AuthDTO{}, exceptions.NewConflictError("Email already in use")
	}

	account, err := s.updateAccountEmailInDB(ctx, logger, accountDTO.ID(), accountDTO.Email, newEmail)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account email", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Updated account email successfully")
	accountDTO = dtos.MapAccountToDTO(&account)
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Email updated successfully",
	)
}

type ConfirmUpdateAccountEmailOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmUpdateAccountEmail(
	ctx context.Context,
	opts ConfirmUpdateAccountEmailOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccountEmail").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account email update...")

	newEmail, exists, err := s.cache.GetUpdateEmailRequest(ctx, cache.GetUpdateEmailRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.PublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get email update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Email update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAccountByEmail(ctx, newEmail); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to check if email exists", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		logger.WarnContext(ctx, "Email already in use")
		return dtos.AuthDTO{}, exceptions.NewConflictError("Email already in use")
	}

	account, err := s.updateAccountEmailInDB(ctx, logger, accountDTO.ID(), accountDTO.Email, newEmail)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account email", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Confirmed account email update successfully")
	accountDTO = dtos.MapAccountToDTO(&account)
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Email updated successfully",
	)
}

func (s *Services) updateAccountPasswordInDB(
	ctx context.Context,
	logger *slog.Logger,
	accountID int32,
	hashedPassword string,
) (database.Account, error) {
	var password pgtype.Text
	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed to scan password to text", "error", err)
		return database.Account{}, err
	}

	account, err := s.database.UpdateAccountPassword(ctx, database.UpdateAccountPasswordParams{
		ID:       accountID,
		Password: password,
	})
	if err != nil {
		return database.Account{}, err
	}

	return account, nil
}

type UpdateAccountPasswordOptions struct {
	RequestID   string
	PublicID    uuid.UUID
	Version     int32
	Password    string
	NewPassword string
}

func (s *Services) UpdateAccountPassword(
	ctx context.Context,
	opts UpdateAccountPasswordOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountPassword").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Updating account password...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: database.AuthProviderUsernamePassword,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Email auth Provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get email auth Provider", "error", err)
		return dtos.AuthDTO{}, serviceErr
	}

	ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare password hash", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Invalid password provided")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if accountDTO.TwoFactorType != database.TwoFactorTypeNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdatePasswordRequest(ctx, cache.SaveUpdatePasswordRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.SensitiveRequestAccountPrefix,
			PublicID:        accountDTO.PublicID,
			NewPassword:     opts.NewPassword,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to cache password update request", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code to confirm password update",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Password update request cached successfully")
		return authDTO, serviceErr
	}

	hashedPassword, err := utils.HashString(opts.NewPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash new password", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	account, err := s.updateAccountPasswordInDB(ctx, logger, accountDTO.ID(), hashedPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account password", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	accountDTO = dtos.MapAccountToDTO(&account)
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Password updated successfully",
	)
}

type ConfirmUpdateAccountPasswordOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmUpdateAccountPassword(
	ctx context.Context,
	opts ConfirmUpdateAccountPasswordOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccountPassword").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account password update...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	newPassword, exists, err := s.cache.GetUpdatePasswordRequest(ctx, cache.GetUpdatePasswordRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   accountDTO.PublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get password update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Password update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	account, err := s.updateAccountPasswordInDB(ctx, logger, accountDTO.ID(), newPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account password", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	accountDTO = dtos.MapAccountToDTO(&account)
	logger.InfoContext(ctx, "Confirmed account password update successfully")
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Password updated successfully",
	)
}

type UpdateAccountOptions struct {
	RequestID  string
	PublicID   uuid.UUID
	Version    int32
	GivenName  string
	FamilyName string
}

func (s *Services) UpdateAccount(
	ctx context.Context,
	opts UpdateAccountOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccount").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Updating account...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AccountDTO{}, serviceErr
	}

	givenName := utils.Capitalized(opts.GivenName)
	familyName := utils.Capitalized(opts.FamilyName)
	account, err := s.database.UpdateAccount(ctx, database.UpdateAccountParams{
		GivenName:  givenName,
		FamilyName: familyName,
		ID:         accountDTO.ID(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated account successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type UpdateAccountUsernameOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Username  string
	Password  string
}

func (s *Services) UpdateAccountUsername(
	ctx context.Context,
	opts UpdateAccountUsernameOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountUsername").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Updating account username...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: database.AuthProviderUsernamePassword,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get email auth Provider", "error", err)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth Provider")
			return dtos.AuthDTO{}, exceptions.NewValidationError("password is required")
		}

		ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to compare password hash", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid password provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	}

	username := utils.Lowered(opts.Username)
	if accountDTO.TwoFactorType != database.TwoFactorTypeNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		if err := s.cache.SaveUpdateUsernameRequest(ctx, cache.SaveUpdateUsernameRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.SensitiveRequestAccountPrefix,
			PublicID:        accountDTO.PublicID,
			Username:        username,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache username update request", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code to confirm username update",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Username update request cached successfully")
		return authDTO, serviceErr
	}

	count, err := s.database.CountAccountByUsername(ctx, username)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account by username", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Username already in use")
		return dtos.AuthDTO{}, exceptions.NewConflictError("Username already in use")
	}

	account, err := s.database.UpdateAccountUsername(ctx, database.UpdateAccountUsernameParams{
		Username: username,
		ID:       accountDTO.ID(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account username", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	accountDTO = dtos.MapAccountToDTO(&account)
	logger.InfoContext(ctx, "Updated account username successfully")
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Username updated successfully",
	)
}

type ConfirmUpdateAccountUsernameOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmUpdateAccountUsername(
	ctx context.Context,
	opts ConfirmUpdateAccountUsernameOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccountUsername").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account username update...")

	newUsername, err := s.cache.GetUpdateUsernameRequest(ctx, cache.GetUpdateUsernameRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.PublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get username update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if newUsername == "" {
		logger.WarnContext(ctx, "Username update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	count, err := s.database.CountAccountByUsername(ctx, newUsername)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account by username", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Username already in use")
		return dtos.AuthDTO{}, exceptions.NewConflictError("Username already in use")
	}

	account, err := s.database.UpdateAccountUsername(ctx, database.UpdateAccountUsernameParams{
		Username: newUsername,
		ID:       accountDTO.ID(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account username", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	accountDTO = dtos.MapAccountToDTO(&account)
	logger.InfoContext(ctx, "Updated account username successfully")
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Username updated successfully",
	)
}

type DeleteAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Password  string
}

func (s *Services) DeleteAccount(
	ctx context.Context,
	opts DeleteAccountOptions,
) (bool, dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "DeleteAccount").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Deleting account...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return false, dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: database.AuthProviderUsernamePassword,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get email auth Provider", "error", err)
			return false, dtos.AuthDTO{}, serviceErr
		}
	} else {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth Provider")
			return false, dtos.AuthDTO{}, exceptions.NewValidationError("password is required")
		}

		ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to compare password hash", "error", err)
			return false, dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid password provided")
			return false, dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	}

	if accountDTO.TwoFactorType != database.TwoFactorTypeNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		if err := s.cache.SaveDeleteAccountRequest(ctx, cache.SaveDeleteAccountRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.SensitiveRequestAccountPrefix,
			PublicID:        accountDTO.PublicID,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache delete account request", "error", err)
			return false, dtos.AuthDTO{}, exceptions.NewServerError()
		}

		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code to confirm account deletion",
		)
		if serviceErr != nil {
			return false, dtos.AuthDTO{}, serviceErr
		}

		logger.InfoContext(ctx, "Delete account request cached successfully")
		return false, authDTO, serviceErr
	}

	if err := s.database.DeleteAccount(ctx, accountDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account", "error", err)
		return false, dtos.AuthDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account deleted successfully")
	return true, dtos.AuthDTO{}, nil
}

type ConfirmDeleteAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmDeleteAccount(
	ctx context.Context,
	opts ConfirmDeleteAccountOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmDeleteAccount").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account deletion...")

	exists, err := s.cache.GetDeleteAccountRequest(ctx, cache.GetDeleteAccountRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.PublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get delete account request", "error", err)
		return exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Delete account request not found")
		return exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return serviceErr
	}

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return serviceErr
	}

	if err := s.database.DeleteAccount(ctx, accountDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account deleted successfully")
	return nil
}

type GetAccountIDByUsernameOptions struct {
	RequestID string
	Username  string
}

func (s *Services) getAccountIDByUsername(
	ctx context.Context,
	opts GetAccountIDByUsernameOptions,
) (int32, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "getAccountIDByUsername")
	logger.InfoContext(ctx, "Getting account ID by username...")

	accountID, err := s.database.FindAccountIDByUsername(ctx, utils.Lowered(opts.Username))
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return 0, serviceErr
		}

		logger.ErrorContext(ctx, "Failed to get account ID", "error", err)
		return 0, serviceErr
	}

	logger.InfoContext(ctx, "Got account ID by username successfully")
	return accountID, nil
}

func (s *Services) GetAndCacheAccountIDByUsername(
	ctx context.Context,
	opts GetAccountIDByUsernameOptions,
) (int32, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAndCacheAccountIDByUsername")
	logger.InfoContext(ctx, "Getting and caching account ID by username...")

	accountID, err := s.cache.GetAccountIDByUsername(ctx, cache.GetAccountIDByUsernameOptions{
		RequestID: opts.RequestID,
		Username:  opts.Username,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account ID from cache", "error", err)
		return 0, exceptions.NewServerError()
	}
	if accountID != 0 {
		logger.InfoContext(ctx, "Got account ID from cache successfully")
		return accountID, nil
	}

	accountID, serviceErr := s.getAccountIDByUsername(ctx, opts)
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account ID", "error", serviceErr)
		return 0, serviceErr
	}

	if err := s.cache.AddAccountUsername(ctx, cache.AddAccountUsernameOptions{
		RequestID: opts.RequestID,
		Username:  opts.Username,
		ID:        accountID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache account ID by username", "error", err)
		return 0, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Cached account ID by username successfully")
	return accountID, nil
}

type UpdateAccountDEKOptions struct {
	RequestID string
	ID        int32
	DEK       string
}

func (s *Services) UpdateAccountDEK(ctx context.Context, opts UpdateAccountDEKOptions) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountDEK").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Updating account DEK...")

	if err := s.database.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
		ID:  opts.ID,
		Dek: opts.DEK,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account DEK", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated account DEK successfully")
	return nil
}

type GetAccountIDByPublicIDAndVersionOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
}

func (s *Services) GetAccountIDByPublicIDAndVersion(
	ctx context.Context,
	opts GetAccountIDByPublicIDAndVersionOptions,
) (int32, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "GetAccountIDByPublicIDAndVersion").With(
		"publicID", opts.PublicID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Getting account ID by public ID and version...")

	accountID, err := s.database.FindAccountIDByPublicIDAndVersion(ctx, database.FindAccountIDByPublicIDAndVersionParams{
		PublicID: opts.PublicID,
		Version:  opts.Version,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "error", err)
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Account not found", "error", err)
			return 0, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "error", err)
		return 0, serviceErr
	}

	logger.InfoContext(ctx, "Got account ID by public ID and version successfully")
	return accountID, nil
}

type updateAccount2FAOptions struct {
	requestID   string
	id          int32
	email       string
	prev2FAType database.TwoFactorType
}

func (s *Services) updateAccountTOTP2FA(
	ctx context.Context,
	opts updateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, authLocation, "updateAccountTOTP2FA").With(
		"id", opts.id,
	)
	logger.InfoContext(ctx, "Update account TOTP 2FA...")

	totpKey, err := s.encrypt.GenerateAccountTotpKey(ctx, encryption.GenerateAccountTotpKeyOptions{
		RequestID: opts.requestID,
		Email:     opts.email,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOTP", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AuthDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	account, err := qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
		TwoFactorType: database.TwoFactorTypeTotp,
		ID:            int32(opts.id),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account 2FA", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}

	if err := qrs.CreateAccountTotps(ctx, database.CreateAccountTotpsParams{
		AccountID:     account.ID,
		Url:           totpKey.URL(),
		Secret:        totpKey.EncryptedSecret(),
		RecoveryCodes: totpKey.HashedCodes(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create account recovery keys", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}

	token, err := s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
		PublicID: account.PublicID,
		Version:  account.Version,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate 2FA access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewAuthDTOWithData(
		token,
		"Please scan QR Code with your authentication app",
		map[string]string{
			"image":         totpKey.Img(),
			"recovery_keys": totpKey.Codes(),
		},
		s.jwt.Get2FATTL(),
	), nil
}

func (s *Services) updateAccountEmail2FA(
	ctx context.Context,
	opts updateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, authLocation, "updateAccountEmail2FA").With(
		"id", opts.id,
	)
	logger.InfoContext(ctx, "Update account email 2FA...")

	code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
		RequestID: opts.requestID,
		AccountID: opts.id,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate two factor Code", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	var account database.Account
	if opts.prev2FAType == database.TwoFactorTypeTotp {
		var serviceErr *exceptions.ServiceError
		qrs, txn, err := s.database.BeginTx(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
			return dtos.AuthDTO{}, exceptions.FromDBError(err)
		}
		defer func() {
			logger.DebugContext(ctx, "Finalizing transaction")
			s.database.FinalizeTx(ctx, txn, err, serviceErr)
		}()

		accountID := int32(opts.id)
		account, err = qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeEmail,
			ID:            accountID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to enable 2FA email", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		if err := qrs.DeleteAccountRecoveryKeys(ctx, accountID); err != nil {
			logger.ErrorContext(ctx, "Failed to delete recovery keys", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		account, err = s.database.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeEmail,
			ID:            int32(opts.id),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to enable 2FA email", "error", err)
			return dtos.AuthDTO{}, exceptions.FromDBError(err)
		}
	}

	if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
		RequestID: opts.requestID,
		Email:     account.Email,
		Name:      fmt.Sprintf("%s %s", account.GivenName, account.FamilyName),
		Code:      code,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	token, err := s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
		PublicID: account.PublicID,
		Version:  account.Version,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate 2FA access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewTempAuthDTO(token, "Please provide email two factor Code", s.jwt.Get2FATTL()), nil
}

func (s *Services) disableAccount2FA(
	ctx context.Context,
	opts updateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, authLocation, "disableAccount2FA").With(
		"id", opts.id,
	)
	logger.InfoContext(ctx, "Update account TOTP 2FA...")

	var account database.Account
	if opts.prev2FAType == database.TwoFactorTypeTotp {
		var serviceErr *exceptions.ServiceError
		qrs, txn, err := s.database.BeginTx(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
			return dtos.AuthDTO{}, exceptions.FromDBError(err)
		}
		defer func() {
			logger.DebugContext(ctx, "Finalizing transaction")
			s.database.FinalizeTx(ctx, txn, err, serviceErr)
		}()

		accountID := int32(opts.id)
		account, err = qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeNone,
			ID:            accountID,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to disable 2FA", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		if err := qrs.DeleteAccountRecoveryKeys(ctx, accountID); err != nil {
			logger.ErrorContext(ctx, "Failed to delete recovery keys", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		var err error
		account, err = s.database.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeNone,
			ID:            int32(opts.id),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to disable 2FA", "error", err)
			return dtos.AuthDTO{}, exceptions.FromDBError(err)
		}
	}

	accountDTO := dtos.MapAccountToDTO(&account)
	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Successfully disabled oauth",
	)
}

type UpdateAccount2FAOptions struct {
	RequestID     string
	PublicID      uuid.UUID
	Version       int32
	TwoFactorType string
	Password      string
}

func (s *Services) UpdateAccount2FA(
	ctx context.Context,
	opts UpdateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccount2FA").With(
		"publicID", opts.PublicID,
		"twoFactorType", opts.TwoFactorType,
	)
	logger.InfoContext(ctx, "Updating account 2FA...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(
		ctx,
		database.FindAccountAuthProviderByEmailAndProviderParams{
			Email:    accountDTO.Email,
			Provider: database.AuthProviderUsernamePassword,
		},
	); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Email auth Provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get auth Provider", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare password hashes", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Passwords do not match")
		return dtos.AuthDTO{}, exceptions.NewValidationError("Passwords do not match")
	}

	twoFactorType, serviceErr := mapTwoFactorType(opts.TwoFactorType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Invalid two factor type", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if accountDTO.TwoFactorType == twoFactorType {
		logger.InfoContext(ctx, "Account already uses given 2FA type")

		token, err := s.jwt.CreateAccessToken(tokens.AccountAccessTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
			Scopes:   []tokens.AccountScope{tokens.AccountScopeAdmin},
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		return dtos.NewAuthDTO(token, s.jwt.GetAccessTTL()), nil
	}

	updateOpts := updateAccount2FAOptions{
		requestID:   opts.RequestID,
		id:          accountDTO.ID(),
		email:       accountDTO.Email,
		prev2FAType: accountDTO.TwoFactorType,
	}
	if accountDTO.TwoFactorType == database.TwoFactorTypeNone {
		switch twoFactorType {
		case database.TwoFactorTypeTotp:
			logger.InfoContext(ctx, "Enabling TOTP 2FA")
			return s.updateAccountTOTP2FA(ctx, updateOpts)
		case database.TwoFactorTypeEmail:
			logger.InfoContext(ctx, "Enabling email 2FA")
			return s.updateAccountEmail2FA(ctx, updateOpts)
		default:
			logger.WarnContext(ctx, "Unknown two factor type, it must be 'totp' or 'email'")
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}
	}

	if err := s.cache.SaveTwoFactorUpdateRequest(ctx, cache.SaveTwoFactorUpdateRequestOptions{
		RequestID:       opts.RequestID,
		PrefixType:      cache.SensitiveRequestAccountPrefix,
		PublicID:        accountDTO.PublicID,
		TwoFactorType:   database.TwoFactorType(opts.TwoFactorType),
		DurationSeconds: s.jwt.GetOAuthTTL(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to save two-factor update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	authDTO, serviceErr := s.generate2FAAuth(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		"Please provide two factor code to confirm two factor update",
	)
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	return authDTO, nil
}

type ConfirmUpdateAccount2FAOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmUpdateAccount2FA(
	ctx context.Context,
	opts ConfirmUpdateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccount2FA").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account 2FA...")

	twoFactorType, err := s.cache.GetTwoFactorUpdateRequest(ctx, cache.GetTwoFactorUpdateRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.SensitiveRequestAccountPrefix,
		PublicID:   opts.PublicID,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get two-factor update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if twoFactorType == "" {
		logger.WarnContext(ctx, "Two-factor update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	updateOpts := updateAccount2FAOptions{
		requestID:   opts.RequestID,
		id:          accountDTO.ID(),
		email:       accountDTO.Email,
		prev2FAType: accountDTO.TwoFactorType,
	}
	switch twoFactorType {
	case database.TwoFactorTypeTotp:
		logger.InfoContext(ctx, "Enabling TOTP 2FA")
		return s.updateAccountTOTP2FA(ctx, updateOpts)
	case database.TwoFactorTypeEmail:
		logger.InfoContext(ctx, "Enabling email 2FA")
		return s.updateAccountEmail2FA(ctx, updateOpts)
	case database.TwoFactorTypeNone:
		logger.InfoContext(ctx, "Disabling 2FA")
		return s.disableAccount2FA(ctx, updateOpts)
	default:
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}
}
