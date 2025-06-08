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

const (
	authLocation string = "auth"

	forgotMessage string = "Reset password email sent if account exists"
	resetMessage  string = "Password reset successfully"
)

func processPurposeAuthHeader(
	authHeader string,
	verify func(string) (tokens.AccountClaims, error),
) (tokens.AccountClaims, *exceptions.ServiceError) {
	token, serviceErr := extractAuthHeaderToken(authHeader)
	if serviceErr != nil {
		return tokens.AccountClaims{}, serviceErr
	}

	accountClaims, err := verify(token)
	if err != nil {
		return tokens.AccountClaims{}, exceptions.NewUnauthorizedError()
	}

	return accountClaims, nil
}

func (s *Services) ProcessAccountAuthHeader(
	authHeader string,
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	token, serviceErr := extractAuthHeaderToken(authHeader)
	if serviceErr != nil {
		return tokens.AccountClaims{}, nil, serviceErr
	}

	accountClaims, scopes, err := s.jwt.VerifyAccessToken(token)
	if err != nil {
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return accountClaims, scopes, nil
}

func (s *Services) Process2FAAuthHeader(
	authHeader string,
) (tokens.AccountClaims, *exceptions.ServiceError) {
	return processPurposeAuthHeader(authHeader, s.jwt.Verify2FAToken)
}

func (s *Services) ProcessOAuthHeader(
	authHeader string,
) (tokens.AccountClaims, *exceptions.ServiceError) {
	return processPurposeAuthHeader(authHeader, s.jwt.VerifyOAuthToken)
}

func (s *Services) GetRefreshTTL() int64 {
	return s.jwt.GetRefreshTTL()
}

func (s *Services) sendConfirmationEmail(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountDTO *dtos.AccountDTO,
) *exceptions.ServiceError {
	confirmationToken, err := s.jwt.CreateConfirmationToken(tokens.AccountAccessTokenOptions{
		PublicID: accountDTO.PublicID,
		Version:  accountDTO.Version(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate confirmation token", "error", err)
		return exceptions.NewServerError()
	}

	if err := s.mail.PublishConfirmationEmail(ctx, mailer.ConfirmationEmailOptions{
		RequestID: requestID,
		Email:     utils.Lowered(accountDTO.Email),
		Name: fmt.Sprintf(
			"%s %s",
			utils.Capitalized(accountDTO.GivenName),
			utils.Capitalized(accountDTO.FamilyName),
		),
		ConfirmationToken: confirmationToken,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish confirmation email", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Sent confirmation email successfully")
	return nil
}

type RegisterAccountOptions struct {
	RequestID string
	Email     string
	GivenName string
	LastName  string
	Password  string
}

func (s *Services) RegisterAccount(
	ctx context.Context,
	opts RegisterAccountOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "RegisterAccount").With(
		"givenName", opts.GivenName,
		"lastName", opts.LastName,
	)
	logger.InfoContext(ctx, "Registering account...")

	accountDTO, serviceErr := s.CreateAccount(ctx, CreateAccountOptions{
		RequestID:  opts.RequestID,
		GivenName:  opts.GivenName,
		FamilyName: opts.LastName,
		Email:      opts.Email,
		Password:   opts.Password,
		Provider:   AuthProviderEmail,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to create account", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	if serviceErr := s.sendConfirmationEmail(ctx, logger, opts.RequestID, &accountDTO); serviceErr != nil {
		return dtos.MessageDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Account registered successfully")
	return dtos.NewMessageDTO("Account registered successfully. Confirmation email has been sent."), nil
}

func (s *Services) GenerateFullAuthDTO(
	ctx context.Context,
	logger *slog.Logger,
	accountDTO *dtos.AccountDTO,
	scopes []tokens.AccountScope,
	logSuccessMessage string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	accessToken, err := s.jwt.CreateAccessToken(tokens.AccountAccessTokenOptions{
		PublicID:     accountDTO.PublicID,
		Version:      accountDTO.Version(),
		Scopes:       scopes,
		TokenSubject: accountDTO.PublicID.String(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	refreshToken, err := s.jwt.CreateRefreshToken(tokens.AccountRefreshTokenOptions{
		PublicID: accountDTO.PublicID,
		Version:  accountDTO.Version(),
		Scopes:   scopes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, logSuccessMessage)
	return dtos.NewFullAuthDTO(accessToken, refreshToken, s.jwt.GetAccessTTL()), nil
}

type ConfirmAccountOptions struct {
	RequestID         string
	ConfirmationToken string
}

func (s *Services) ConfirmAccount(
	ctx context.Context,
	opts ConfirmAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ConfirmAccount")
	logger.InfoContext(ctx, "Confirming user...")

	claims, err := s.jwt.VerifyConfirmationToken(opts.ConfirmationToken)
	if err != nil {
		logger.InfoContext(ctx, "Failed to verify confirmation token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  claims.AccountID,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by token AccountID", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if claims.AccountVersion != accountVersion {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.AccountVersion,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if accountDTO.EmailVerified() {
		logger.WarnContext(ctx, "Account is already confirmed")
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Confirmed Account successfully",
	)
}

type LoginAccountOptions struct {
	RequestID string
	Email     string
	Password  string
}

func (s *Services) LoginAccount(
	ctx context.Context,
	opts LoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "LoginAccount")
	logger.InfoContext(ctx, "Logging in account...")

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.RequestID,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	passwordVerified, err := utils.CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !passwordVerified {
		logger.WarnContext(ctx, "Passwords do not match")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if !accountDTO.EmailVerified() {
		logger.InfoContext(ctx, "Account is not confirmed, sending new confirmation email")

		if serviceErr := s.sendConfirmationEmail(ctx, logger, opts.RequestID, &accountDTO); serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorEmail, TwoFactorTotp:
		twoFAToken, err := s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate 2FA JWT", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		if accountDTO.TwoFactorType == TwoFactorEmail {
			code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID(),
				TTL:       s.jwt.Get2FATTL(),
			})
			if err != nil {
				logger.ErrorContext(ctx, "Failed to generate two factor Code", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}

			if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
				RequestID: opts.RequestID,
				Email:     opts.Email,
				Name:      fmt.Sprintf("%s %s", accountDTO.GivenName, accountDTO.FamilyName),
				Code:      code,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}
		}

		return dtos.NewTempAuthDTO(
			twoFAToken,
			"Please provide two factor Code",
			s.jwt.Get2FATTL(),
		), nil
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Logged in account successfully",
	)
}

type VerifyAccountTotpOptions struct {
	RequestID string
	ID        int32
	Code      string
	DEK       string
}

func (s *Services) VerifyAccountTotp(
	ctx context.Context,
	opts VerifyAccountTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "VerifyAccountTotp").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Verifying account TOTP...")

	accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, opts.ID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account TOTP not found", "error", err)
			return false, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
		return false, serviceErr
	}

	ok, newDEK, err := s.encrypt.VerifyTotpCode(ctx, encryption.VerifyAccountTotpCodeOptions{
		RequestID:       opts.RequestID,
		EncryptedSecret: accountTOTP.Secret,
		StoredDEK:       opts.DEK,
		Code:            opts.Code,
		TotpType:        encryption.TotpTypeAccount,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", err)
		return false, exceptions.NewServerError()
	}

	if newDEK != "" {
		logger.InfoContext(ctx, "Saving new StoredDEK")
		if err := s.database.UpdateAccountDEK(ctx, database.UpdateAccountDEKParams{
			Dek: newDEK,
			ID:  opts.ID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account TOTP StoredDEK", "error", err)
			return false, exceptions.FromDBError(err)
		}
	}

	return ok, nil
}

type TwoFactorLoginAccountOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) TwoFactorLoginAccount(
	ctx context.Context,
	opts TwoFactorLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "TwoFactorLoginAccount")
	logger.InfoContext(ctx, "2FA logging in account...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	logger = logger.With("accountId", accountDTO.ID())
	accountVersion := accountDTO.Version()
	if accountVersion != opts.Version {
		logger.WarnContext(ctx, "Account versions do not match",
			"accessTokenVersion", opts.Version,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	var ok bool
	var err error
	switch accountDTO.TwoFactorType {
	case TwoFactorNone:
		logger.WarnContext(ctx, "User has two factor inactive")
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	case TwoFactorTotp:
		ok, serviceErr = s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: opts.RequestID,
			ID:        accountDTO.ID(),
			Code:      opts.Code,
			DEK:       accountDTO.DEK(),
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
	case TwoFactorEmail:
		ok, err = s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Error verifying Code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	}

	if !ok {
		logger.WarnContext(ctx, "Failed to verify Code")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"2FA Logged in successfully",
	)
}

type LogoutAccountOptions struct {
	RequestID    string
	RefreshToken string
}

func (s *Services) LogoutAccount(
	ctx context.Context,
	opts LogoutAccountOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.RequestID, authLocation, "LogoutAccount")
	logger.InfoContext(ctx, "Logging out account...")

	claims, _, tokenID, exp, err := s.jwt.VerifyRefreshToken(opts.RefreshToken)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify refresh token", "error", err)
		return exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  uuid.UUID(claims.AccountID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to find account of refresh token")
		return exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if accountVersion != claims.AccountVersion {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.AccountVersion,
			"accountVersion", accountVersion,
		)
		return exceptions.NewUnauthorizedError()
	}

	blt, err := s.database.GetBlacklistedToken(ctx, tokenID)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch blacklisted token", "error", err)
			return exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is blacklisted", "blacklistedAt", blt.CreatedAt)
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.BlacklistToken(ctx, database.BlacklistTokenParams{
		ID:        tokenID,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to blacklist the token", "error", err)
		return exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Logged out account successfully")
	return nil
}

type RefreshTokenAccountOptions struct {
	RequestID    string
	RefreshToken string
}

func (s *Services) RefreshTokenAccount(
	ctx context.Context,
	opts RefreshTokenAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "RefreshTokenAccount")
	logger.InfoContext(ctx, "Refreshing account access token...")

	claims, scopes, id, exp, err := s.jwt.VerifyRefreshToken(opts.RefreshToken)
	if err != nil {
		logger.WarnContext(ctx, "Invalid refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	blt, err := s.database.GetBlacklistedToken(ctx, id)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get blacklisted token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is blacklisted", "blacklistedAt", blt.CreatedAt)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  claims.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "error", serviceErr)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accountVersion := accountDTO.Version()
	if accountVersion != claims.AccountVersion {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.AccountVersion,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if err := s.database.BlacklistToken(ctx, database.BlacklistTokenParams{
		ID:        id,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to blacklist previous refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		scopes,
		"Refreshed access token successfully",
	)
}

type ForgoutAccountPasswordOptions struct {
	RequestID string
	Email     string
}

func (s *Services) ForgoutAccountPassword(
	ctx context.Context,
	opts ForgoutAccountPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ForgoutAccountPassword")
	logger.InfoContext(ctx, "Forgout account password...")

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions(opts))
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found")
			return dtos.NewMessageDTO(forgotMessage), nil
		}

		logger.ErrorContext(ctx, "Failed get account by email", "serviceErr", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	resetToken, err := s.jwt.CreateResetToken(tokens.AccountResetTokenOptions{
		PublicID: accountDTO.PublicID,
		Version:  accountDTO.Version(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate rest token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := s.mail.PublishResetEmail(ctx, mailer.ResetEmailOptions{
		RequestID: opts.RequestID,
		Email:     accountDTO.Email,
		Name: fmt.Sprintf(
			"%s %s",
			utils.Capitalized(accountDTO.GivenName),
			utils.Capitalized(accountDTO.FamilyName),
		),
		ResetToken: resetToken,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish reset email", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Reset email sent successfully")
	return dtos.NewMessageDTO(forgotMessage), nil
}

type ResetAccountPasswordOptions struct {
	RequestID  string
	ResetToken string
	Password   string
}

func (s *Services) ResetAccountPassword(
	ctx context.Context,
	opts ResetAccountPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ResetAccountPassword")
	logger.InfoContext(ctx, "Reset account password...")

	accountClaims, err := s.jwt.VerifyResetToken(opts.ResetToken)
	if err != nil {
		logger.InfoContext(ctx, "Failed to verify reset token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  accountClaims.AccountID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account not found", "error", serviceErr)
			return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	accountVersion := accountDTO.Version()
	if accountVersion != accountClaims.AccountVersion {
		logger.WarnContext(ctx, "Account and claims versions do not match",
			"accountVersion", accountVersion,
			"claimsVersion", accountClaims.AccountVersion,
		)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	var password pgtype.Text
	hashedPassword, err := utils.HashString(opts.Password)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to hash password", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
		return dtos.MessageDTO{}, exceptions.NewServerError()
	}

	if _, err := s.database.UpdateAccountPassword(ctx, database.UpdateAccountPasswordParams{
		Password: password,
		ID:       accountDTO.ID(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update account password", "error", err)
		return dtos.MessageDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Account password reset successfully")
	return dtos.NewMessageDTO(resetMessage), nil
}

type updateAccount2FAOptions struct {
	requestID   string
	id          int32
	email       string
	prev2FAType string
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
	if opts.prev2FAType == TwoFactorTotp {
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
			TwoFactorType: TwoFactorTotp,
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
			TwoFactorType: TwoFactorTotp,
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
		TwoFactorType: TwoFactorTotp,
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
	if opts.prev2FAType == TwoFactorTotp {
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
			TwoFactorType: TwoFactorEmail,
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
			TwoFactorType: TwoFactorEmail,
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

type UpdateAccount2FAOptions struct {
	RequestID     string
	PublicID      uuid.UUID
	TwoFactorType string
	Password      string
}

func (s *Services) UpdateAccount2FA(
	ctx context.Context,
	opts UpdateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "UpdateAccount2FA").With(
		"publicID", opts.PublicID,
		"twoFactorType", opts.TwoFactorType,
	)
	logger.InfoContext(ctx, "Updating account 2FA...")

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
	})
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	if _, err := s.database.FindAuthProviderByEmailAndProvider(
		ctx,
		database.FindAuthProviderByEmailAndProviderParams{
			Email:    accountDTO.Email,
			Provider: AuthProviderEmail,
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

	if accountDTO.TwoFactorType == opts.TwoFactorType {
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

	ok, err := utils.CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare password hashes", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Passwords do not match")
		return dtos.AuthDTO{}, exceptions.NewValidationError("Passwords do not match")
	}

	updateOpts := updateAccount2FAOptions{
		requestID:   opts.RequestID,
		id:          accountDTO.ID(),
		email:       accountDTO.Email,
		prev2FAType: accountDTO.TwoFactorType,
	}
	switch opts.TwoFactorType {
	case TwoFactorNone:
		logger.InfoContext(ctx, "Disabling account 2FA")
		return s.disableAccount2FA(ctx, updateOpts)
	case TwoFactorTotp:
		logger.InfoContext(ctx, "Enabling TOTP 2FA")
		return s.updateAccountTOTP2FA(ctx, updateOpts)
	case TwoFactorEmail:
		logger.InfoContext(ctx, "Enabling email 2FA")
		return s.updateAccountEmail2FA(ctx, updateOpts)
	default:
		logger.WarnContext(ctx, "Unknown two factor type, it must be 'none', 'totp' or 'email'")
		return dtos.AuthDTO{}, exceptions.NewForbiddenError()
	}
}
