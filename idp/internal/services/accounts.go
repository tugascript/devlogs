// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
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

	if accountDTO.TwoFactorType != TwoFactorNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdateEmailRequest(ctx, cache.SaveUpdateEmailRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.EmailUpdateAccountPrefix,
			PublicID:        accountDTO.PublicID,
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
		PrefixType: cache.EmailUpdateAccountPrefix,
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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
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
			AccountID: accountDTO.ID(),
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA Code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA Code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: opts.RequestID,
			ID:        accountDTO.ID(),
			Code:      opts.Code,
			DEK:       accountDTO.DEK(),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP Code provided")
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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
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

	if accountDTO.TwoFactorType != TwoFactorNone {
		logger.InfoContext(ctx, "Account has 2FA enabled", "twoFactorType", accountDTO.TwoFactorType)

		err = s.cache.SaveUpdatePasswordRequest(ctx, cache.SaveUpdatePasswordRequestOptions{
			RequestID:       opts.RequestID,
			PrefixType:      cache.PasswordUpdateAccountPrefix,
			PublicID:        accountDTO.PublicID,
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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	newPassword, exists, err := s.cache.GetUpdatePasswordRequest(ctx, cache.GetUpdatePasswordRequestOptions{
		RequestID:  opts.RequestID,
		PrefixType: cache.PasswordUpdateAccountPrefix,
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

	switch accountDTO.TwoFactorType {
	case TwoFactorNone:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	case TwoFactorEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA Code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA Code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: opts.RequestID,
			ID:        accountDTO.ID(),
			Code:      opts.Code,
			DEK:       accountDTO.DEK(),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP Code provided")
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
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
	GivenName  string
	FamilyName string
	Username   string
}

func (s *Services) UpdateAccount(
	ctx context.Context,
	opts UpdateAccountOptions,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccount").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Updating account...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AccountDTO{}, serviceErr
	}

	username := utils.Lowered(opts.Username)
	count, err := s.database.CountAccountByUsername(ctx, username)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count account by username", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}
	if count > 0 {
		logger.WarnContext(ctx, "Username already in use")
		return dtos.AccountDTO{}, exceptions.NewConflictError("Username already in use")
	}

	givenName := utils.Capitalized(opts.GivenName)
	familyName := utils.Capitalized(opts.FamilyName)
	account, err := s.database.UpdateAccount(ctx, database.UpdateAccountParams{
		GivenName:  givenName,
		FamilyName: familyName,
		Username:   username,
		ID:         accountDTO.ID(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account", "error", err)
		return dtos.AccountDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Updated account successfully")
	return dtos.MapAccountToDTO(&account), nil
}

type DeleteAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Password  string
}

func (s *Services) DeleteAccount(
	ctx context.Context,
	opts DeleteAccountOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "DeleteAccount").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Deleting account...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return false, serviceErr
	}

	if _, err := s.database.FindAccountAuthProviderByEmailAndProvider(ctx, database.FindAccountAuthProviderByEmailAndProviderParams{
		Email:    accountDTO.Email,
		Provider: database.AuthProviderUsernamePassword,
	}); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get email auth Provider", "error", err)
			return false, serviceErr
		}
	} else {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth Provider")
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
			PublicID:        accountDTO.PublicID,
			DurationSeconds: s.jwt.GetOAuthTTL(),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to cache delete account request", "error", err)
			return false, exceptions.NewServerError()
		}

		logger.InfoContext(ctx, "Delete account request cached successfully")
		return false, nil
	}

	if err := s.database.DeleteAccount(ctx, accountDTO.ID()); err != nil {
		logger.ErrorContext(ctx, "Failed to delete account", "error", err)
		return false, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account deleted successfully")
	return true, nil
}

type ConfirmDeleteAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
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
		PrefixType: cache.DeleteAccountAccountPrefix,
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

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		logger.InfoContext(ctx, "Failed to get account", "error", serviceErr)
		return serviceErr
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to verify 2FA Code", "error", err)
			return exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid 2FA Code provided")
			return exceptions.NewUnauthorizedError()
		}
	case TwoFactorTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: opts.RequestID,
			ID:        accountDTO.ID(),
			Code:      opts.Code,
			DEK:       accountDTO.DEK(),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
			return serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Invalid TOTP Code provided")
			return exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Account has no 2FA enabled")
		return exceptions.NewUnauthorizedError()
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
