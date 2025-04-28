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

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const accountsLocation = "accounts"

type CreateAccountOptions struct {
	RequestID string
	FirstName string
	LastName  string
	Email     string
	Password  string
	Provider  string
}

func (s *Services) CreateAccount(
	ctx context.Context,
	opts CreateAccountOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "CreateAccount").With(
		"firstName", opts.FirstName,
		"lastName", opts.LastName,
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Creating account...")

	var provider string
	var password pgtype.Text
	switch opts.Provider {
	case AuthProviderEmail:
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth provider")
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

		provider = AuthProviderEmail
	case AuthProviderApple, AuthProviderFacebook, AuthProviderGoogle, AuthProviderGitHub, AuthProviderMicrosoft:
		provider = opts.Provider
	default:
		logger.ErrorContext(ctx, "Provider must be 'email', 'apple', 'facebook', 'github', 'google' or 'microsoft'")
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}

	email := utils.Lowered(opts.Email)
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

	firstName := utils.Capitalized(opts.FirstName)
	lastName := utils.Capitalized(opts.LastName)
	username := utils.Slugify(fmt.Sprintf("%s %s", firstName, lastName))
	count, err := s.database.CountAccountAlikeUsernames(ctx, utils.DbSearchEnd(username))
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count usernames that are alike", "error", err)
		return dtos.AccountDTO{}, exceptions.NewServerError()
	}
	if count > 0 {
		username = fmt.Sprintf("%s%d", username, count+1)
	}

	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	var account database.Account
	if provider == AuthProviderEmail {
		account, err = qrs.CreateAccountWithPassword(ctx, database.CreateAccountWithPasswordParams{
			FirstName: firstName,
			LastName:  lastName,
			Username:  username,
			Email:     email,
			Password:  password,
		})
	} else {
		account, err = qrs.CreateAccountWithoutPassword(ctx, database.CreateAccountWithoutPasswordParams{
			FirstName: firstName,
			LastName:  lastName,
			Username:  username,
			Email:     email,
		})
	}

	if err := qrs.CreateAuthProvider(ctx, database.CreateAuthProviderParams{
		Email:    email,
		Provider: provider,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create auth provider", "error", err)
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

	// Update account email
	account, err := qrs.UpdateAccountEmail(ctx, database.UpdateAccountEmailParams{
		ID:    accountID,
		Email: newEmail,
	})
	if err != nil {
		return database.Account{}, err
	}

	// Delete external auth providers since they won't be valid anymore
	err = qrs.DeleteExternalAuthProviders(ctx, database.DeleteExternalAuthProvidersParams{
		Email:    oldEmail,
		Provider: AuthProviderEmail,
	})
	if err != nil {
		return database.Account{}, err
	}

	return account, nil
}

type UpdateAccountEmailOptions struct {
	RequestID string
	ID        int32
	Email     string
	Password  string
}

func (s *Services) UpdateAccountEmail(
	ctx context.Context,
	opts UpdateAccountEmailOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountEmail").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Updating account email...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	_, err := s.database.FindAuthProviderByEmailAndProvider(ctx, database.FindAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: AuthProviderEmail,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Email auth provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get email auth provider", "error", err)
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

	if accountDTO.TwoFactorType != TwoFactorNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdateEmailRequest(ctx, cache.SaveUpdateEmailRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.EmailUpdateAccountPrefix,
			ID:              int(opts.ID),
			Email:           opts.Email,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to cache email update request", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		return dtos.AuthDTO{}, nil
	}

	newEmail := utils.Lowered(opts.Email)
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

	account, err := s.updateAccountEmailInDB(ctx, logger, opts.ID, accountDTO.Email, newEmail)
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
	ID        int32
	Code      string
}

func (s *Services) ConfirmUpdateAccountEmail(
	ctx context.Context,
	opts ConfirmUpdateAccountEmailOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccountEmail").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Confirming account email update...")

	// Get the cached email update request
	newEmail, exists, err := s.cache.GetUpdateEmailRequest(ctx, cache.GetUpdateEmailRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.EmailUpdateAccountPrefix,
		ID:         int(opts.ID),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get email update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Email update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	// Verify 2FA code
	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorNone:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	case TwoFactorEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID,
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions(opts))
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
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

	account, err := s.updateAccountEmailInDB(ctx, logger, opts.ID, accountDTO.Email, newEmail)
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
	ID          int32
	Password    string
	NewPassword string
}

func (s *Services) UpdateAccountPassword(
	ctx context.Context,
	opts UpdateAccountPasswordOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccountPassword").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Updating account password...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	_, err := s.database.FindAuthProviderByEmailAndProvider(ctx, database.FindAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: AuthProviderEmail,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.InfoContext(ctx, "Email auth provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get email auth provider", "error", err)
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

	if accountDTO.TwoFactorType != TwoFactorNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdatePasswordRequest(ctx, cache.SaveUpdatePasswordRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.PasswordUpdateAccountPrefix,
			ID:              int(opts.ID),
			NewPassword:     opts.NewPassword,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to cache password update request", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Password update request cached successfully")
		return dtos.AuthDTO{}, nil
	}

	hashedPassword, err := utils.HashString(opts.NewPassword)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash new password", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	account, err := s.updateAccountPasswordInDB(ctx, logger, opts.ID, hashedPassword)
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
	ID        int32
	Code      string
}

func (s *Services) ConfirmUpdateAccountPassword(
	ctx context.Context,
	opts ConfirmUpdateAccountPasswordOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmUpdateAccountPassword").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Confirming account password update...")

	// Get the cached password update request
	newPassword, exists, err := s.cache.GetUpdatePasswordRequest(ctx, cache.GetUpdatePasswordRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.PasswordUpdateAccountPrefix,
		ID:         int(opts.ID),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get password update request", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Password update request not found")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	// Verify 2FA code
	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorNone:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	case TwoFactorEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID,
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions(opts))
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	account, err := s.updateAccountPasswordInDB(ctx, logger, opts.ID, newPassword)
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

type DeleteAccountOptions struct {
	RequestID string
	ID        int32
	Password  string
}

func (s *Services) DeleteAccount(
	ctx context.Context,
	opts DeleteAccountOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "DeleteAccount").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Deleting account...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return false, serviceErr
	}

	_, err := s.database.FindAuthProviderByEmailAndProvider(ctx, database.FindAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: AuthProviderEmail,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get email auth provider", "error", err)
			return false, serviceErr
		}
	} else {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth provider")
			return false, exceptions.NewValidationError("password is required")
		}

		ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to compare password hash", "error", err)
			return false, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid password provided")
			return false, exceptions.NewUnauthorizedError()
		}
	}

	if accountDTO.TwoFactorType != TwoFactorNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		if err := s.cache.SaveDeleteAccountRequest(ctx, cache.SaveDeleteAccountRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.DeleteAccountAccountPrefix,
			ID:              accountDTO.ID,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache delete account request", "error", err)
			return false, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Delete account request cached successfully")
		return false, nil
	}

	if err := s.database.DeleteAccount(ctx, opts.ID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account", "error", err)
		return false, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account deleted successfully")
	return true, nil
}

type ConfirmDeleteAccountOptions struct {
	RequestID string
	ID        int32
	Code      string
}

func (s *Services) ConfirmDeleteAccount(
	ctx context.Context,
	opts ConfirmDeleteAccountOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "ConfirmDeleteAccount").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Confirming account deletion...")

	// Get the cached delete account request
	exists, err := s.cache.GetDeleteAccountRequest(ctx, cache.GetDeleteAccountRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.DeleteAccountAccountPrefix,
		ID:         int(opts.ID),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get delete account request", "error", err)
		return exceptions.NewServerError()
	}
	if !exists {
		logger.WarnContext(ctx, "Delete account request not found")
		return exceptions.NewUnauthorizedError()
	}

	// Verify 2FA code
	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return serviceErr
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID,
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA code", "error", err)
			return exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA code provided")
			return exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions(opts))
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", serviceErr)
			return serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP code provided")
			return exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.DeleteAccount(ctx, opts.ID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account deleted successfully")
	return nil
}
