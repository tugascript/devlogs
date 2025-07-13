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
	"regexp"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
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

type processPurposeAuthHeaderOptions struct {
	requestID    string
	authHeader   string
	tokenPurpose tokens.TokenPurpose
	tokenKeyType database.TokenKeyType
}

func (s *Services) processPurposeAuthHeader(
	ctx context.Context,
	opts processPurposeAuthHeaderOptions,
) (tokens.AccountClaims, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, authLocation, "processPurposeAuthHeader")
	logger.InfoContext(ctx, "Processing purpose auth header...")

	token, serviceErr := extractAuthHeaderToken(opts.authHeader)
	if serviceErr != nil {
		return tokens.AccountClaims{}, serviceErr
	}

	accountClaims, err := s.jwt.VerifyPurposeToken(
		token,
		opts.tokenPurpose,
		s.buildGetVerifyKeyFn(ctx, logger, opts.requestID, opts.tokenKeyType),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify purpose token", "error", err)
		return tokens.AccountClaims{}, exceptions.NewUnauthorizedError()
	}

	return accountClaims, nil
}

type ProcessAuthHeaderOptions struct {
	RequestID  string
	AuthHeader string
}

func (s *Services) ProcessAccountAuthHeader(
	ctx context.Context,
	opts ProcessAuthHeaderOptions,
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ProcessAccountAuthHeader")
	logger.InfoContext(ctx, "Processing account auth header...")

	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		return tokens.AccountClaims{}, nil, serviceErr
	}

	accountClaims, scopes, err := s.jwt.VerifyAccessToken(
		token,
		s.buildGetVerifyKeyFn(ctx, logger, opts.RequestID, database.TokenKeyTypeAccess),
	)
	if err != nil {
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return accountClaims, scopes, nil
}

func (s *Services) Process2FAAuthHeader(
	ctx context.Context,
	opts ProcessAuthHeaderOptions,
) (tokens.AccountClaims, *exceptions.ServiceError) {
	return s.processPurposeAuthHeader(
		ctx,
		processPurposeAuthHeaderOptions{
			requestID:    opts.RequestID,
			authHeader:   opts.AuthHeader,
			tokenPurpose: tokens.TokenPurpose2FA,
			tokenKeyType: database.TokenKeyType2faAuthentication,
		},
	)
}

func (s *Services) ProcessOAuthHeader(
	ctx context.Context,
	opts ProcessAuthHeaderOptions,
) (tokens.AccountClaims, *exceptions.ServiceError) {
	return s.processPurposeAuthHeader(
		ctx,
		processPurposeAuthHeaderOptions{
			requestID:    opts.RequestID,
			authHeader:   opts.AuthHeader,
			tokenPurpose: tokens.TokenPurposeOAuth,
			tokenKeyType: database.TokenKeyTypeOauthAuthorization,
		},
	)
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
	signedToken, err := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token: s.jwt.CreateConfirmationToken(tokens.AccountConfirmationTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: requestID,
			keyType:   database.TokenKeyTypeEmailVerification,
			ttl:       s.jwt.GetConfirmationTTL(),
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to sign confirmation token", "error", err)
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
		ConfirmationToken: signedToken,
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
	Username  string
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
		Username:   opts.Username,
		Provider:   AuthProviderUsernamePassword,
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
	requestID string,
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

	signedAccessToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     accessToken,
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: requestID,
			keyType:   database.TokenKeyTypeAccess,
			ttl:       s.jwt.GetAccessTTL(),
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign access token", "serviceError", serviceErr)
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

	signedRefreshToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     refreshToken,
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: requestID,
			keyType:   database.TokenKeyTypeRefresh,
			ttl:       s.jwt.GetRefreshTTL(),
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign refresh token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, logSuccessMessage)
	return dtos.NewFullAuthDTO(signedAccessToken, signedRefreshToken, s.jwt.GetAccessTTL()), nil
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

	claims, err := s.jwt.VerifyPurposeToken(
		opts.ConfirmationToken,
		tokens.TokenPurposeConfirmation,
		s.buildGetVerifyKeyFn(ctx, logger, opts.RequestID, database.TokenKeyTypeEmailVerification),
	)
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
		opts.RequestID,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Confirmed Account successfully",
	)
}

func (s *Services) generate2FAAuth(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountDTO *dtos.AccountDTO,
	msg string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	twoFAToken, err := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: requestID,
			keyType:   database.TokenKeyType2faAuthentication,
			ttl:       s.jwt.Get2FATTL(),
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	if accountDTO.TwoFactorType == database.TwoFactorTypeEmail {
		code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
			RequestID: requestID,
			AccountID: accountDTO.ID(),
			TTL:       s.jwt.Get2FATTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate two factor Code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
			RequestID: requestID,
			Email:     accountDTO.Email,
			Name:      fmt.Sprintf("%s %s", accountDTO.GivenName, accountDTO.FamilyName),
			Code:      code,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	}

	return dtos.NewTempAuthDTO(
		twoFAToken,
		msg,
		s.jwt.Get2FATTL(),
	), nil
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

	passwordVerified, err := utils.Argon2CompareHash(opts.Password, accountDTO.Password())
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
	case database.TwoFactorTypeEmail, database.TwoFactorTypeTotp:
		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			"Please provide two factor code",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
		return authDTO, nil
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"Logged in account successfully",
	)
}

type VerifyAccountTotpOptions struct {
	RequestID string
	ID        int32
	Code      string
}

func (s *Services) VerifyAccountTotp(
	ctx context.Context,
	opts VerifyAccountTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "VerifyAccountTotp").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Verifying account TOTP...")

	verified, serviceErr := s.crypto.VerifyTotpCode(ctx, crypto.VerifyTotpCodeOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
		OwnerID:   opts.ID,
		GetSecret: func(ownerID int32) (crypto.EncryptedTOTPSecret, crypto.DEKID, *exceptions.ServiceError) {
			accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, opts.ID)
			if err != nil {
				serviceErr := exceptions.FromDBError(err)
				if serviceErr.Code == exceptions.CodeNotFound {
					logger.WarnContext(ctx, "Account TOTP not found", "error", err)
					return "", "", exceptions.NewForbiddenError()
				}

				logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
				return "", "", serviceErr
			}

			return accountTOTP.Secret, accountTOTP.DekKid, nil
		},
		GetDEKfn: s.buildGetGlobalDecDEKFn(ctx, logger, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
		return false, serviceErr
	}

	return verified, nil
}

func (s *Services) verifyAccountTwoFactor(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountDTO *dtos.AccountDTO,
	code string,
) *exceptions.ServiceError {
	switch accountDTO.TwoFactorType {
	case database.TwoFactorTypeNone:
		logger.WarnContext(ctx, "User has two factor inactive")
		return exceptions.NewForbiddenError()
	case database.TwoFactorTypeTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: requestID,
			ID:        accountDTO.ID(),
			Code:      code,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
			return serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Failed to verify TOTP Code")
			return exceptions.NewUnauthorizedError()
		}
	case database.TwoFactorTypeEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: requestID,
			AccountID: accountDTO.ID(),
			Code:      code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Error verifying Code", "error", err)
			return exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Failed to verify Code")
			return exceptions.NewUnauthorizedError()
		}
	}

	return nil
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

	if serviceErr := s.verifyAccountTwoFactor(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		opts.Code,
	); serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		opts.RequestID,
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

	claims, _, tokenID, exp, err := s.jwt.VerifyRefreshToken(
		opts.RefreshToken,
		s.buildGetVerifyKeyFn(ctx, logger, opts.RequestID, database.TokenKeyTypeRefresh),
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify refresh token", "error", err)
		return exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  claims.AccountID,
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

	blt, err := s.database.GetRevokedToken(ctx, tokenID)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch revoked token", "error", err)
			return exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is revoked", "revokedAt", blt.CreatedAt)
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.RevokeToken(ctx, database.RevokeTokenParams{
		TokenID:   tokenID,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to revoke the token", "error", err)
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

	claims, scopes, id, exp, err := s.jwt.VerifyRefreshToken(
		opts.RefreshToken,
		s.buildGetVerifyKeyFn(ctx, logger, opts.RequestID, database.TokenKeyTypeRefresh),
	)
	if err != nil {
		logger.WarnContext(ctx, "Invalid refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	blt, err := s.database.GetRevokedToken(ctx, id)
	if err != nil {
		if exceptions.FromDBError(err).Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get blacklisted token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	} else {
		logger.WarnContext(ctx, "Token is revoked", "revokedAt", blt.CreatedAt)
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

	if err := s.database.RevokeToken(ctx, database.RevokeTokenParams{
		TokenID:   id,
		ExpiresAt: exp,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to blacklist previous refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		opts.RequestID,
		&accountDTO,
		scopes,
		"Refreshed access token successfully",
	)
}

type ForgotAccountPasswordOptions struct {
	RequestID string
	Email     string
}

func (s *Services) ForgotAccountPassword(
	ctx context.Context,
	opts ForgotAccountPasswordOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ForgotAccountPassword")
	logger.InfoContext(ctx, "Forgot account password...")

	accountDTO, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions(opts))
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound || serviceErr.Code == exceptions.CodeUnauthorized {
			logger.WarnContext(ctx, "Account not found")
			return dtos.NewMessageDTO(forgotMessage), nil
		}

		logger.ErrorContext(ctx, "Failed get account by email", "serviceErr", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	signedToken, err := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.CreateResetToken(tokens.AccountResetTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: opts.RequestID,
			keyType:   database.TokenKeyTypePasswordReset,
			ttl:       s.jwt.GetResetTTL(),
		}),
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
		ResetToken: signedToken,
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

	accountClaims, err := s.jwt.VerifyPurposeToken(
		opts.ResetToken,
		tokens.TokenPurposeReset,
		s.buildGetVerifyKeyFn(ctx, logger, opts.RequestID, database.TokenKeyTypePasswordReset),
	)
	if err != nil {
		logger.InfoContext(ctx, "Failed to verify reset token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  accountClaims.AccountID,
		Version:   accountClaims.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.MessageDTO{}, serviceErr
	}

	var password pgtype.Text
	hashedPassword, err := utils.Argon2HashString(opts.Password)
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

var recoveryRegex = regexp.MustCompile(`^[A-Z0-9]{4}(?:-[A-Z0-9]{4})*$`)

func isValidRecoveryCode(code string) bool {
	if code == "" || len(code) < 16 {
		return false
	}

	return recoveryRegex.MatchString(code)
}

type RecoverAccountOptions struct {
	RequestID    string
	PublicID     uuid.UUID
	Version      int32
	RecoveryCode string
}

func (s *Services) RecoverAccount(
	ctx context.Context,
	opts RecoverAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "RecoverAccount").With(
		"publicID", opts.PublicID,
		"version", opts.Version,
	)
	logger.InfoContext(ctx, "Recovering account...")

	if !isValidRecoveryCode(opts.RecoveryCode) {
		logger.WarnContext(ctx, "Invalid recovery code format", "recoveryCode", opts.RecoveryCode)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account by public ID and version", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}
	if accountDTO.TwoFactorType != database.TwoFactorTypeTotp {
		logger.WarnContext(ctx, "Account does not have TOTP enabled")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, accountDTO.ID())
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account TOTP not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
		return dtos.AuthDTO{}, serviceErr
	}

	ok, newTotpKey, serviceErr := s.crypto.VerifyTotpRecoveryCode(ctx, crypto.VerifyTotpRecoveryCodeOptions{
		RequestID:    opts.RequestID,
		Email:        accountDTO.Email,
		RecoveryCode: opts.RecoveryCode,
		OwnerID:      accountDTO.ID(),
		GetCodes: func(ownerID int32) ([]byte, *exceptions.ServiceError) {
			accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, accountDTO.ID())
			if err != nil {
				serviceErr := exceptions.FromDBError(err)
				if serviceErr.Code == exceptions.CodeNotFound {
					logger.WarnContext(ctx, "Account TOTP not found", "error", err)
					return nil, exceptions.NewForbiddenError()
				}

				logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
				return nil, serviceErr
			}

			return accountTOTP.RecoveryCodes, nil
		},
		GetDEKfn: s.buildGetEncGlobalDEK(ctx, logger, opts.RequestID),
		StoreTOTPfn: func(encSecret string, hashedCode []byte, url string) *exceptions.ServiceError {
			if err := s.database.UpdateAccountTotp(ctx, database.UpdateAccountTotpParams{
				ID:            accountTOTP.ID,
				Secret:        encSecret,
				RecoveryCodes: hashedCode,
				Url:           url,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to update account TOTP", "error", err)
				return exceptions.FromDBError(err)
			}

			return nil
		},
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP recovery code", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Failed to verify TOTP recovery code")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: opts.RequestID,
			keyType:   database.TokenKeyType2faAuthentication,
			ttl:       s.jwt.Get2FATTL(),
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	authDTOData := map[string]string{
		"image": newTotpKey.Img(),
	}
	if newTotpKey.Codes() != "" {
		authDTOData["recovery_keys"] = newTotpKey.Codes()
	}

	return dtos.NewAuthDTOWithData(
		signedToken,
		"Please scan QR Code with your authentication app",
		authDTOData,
		s.jwt.Get2FATTL(),
	), nil
}

type ListAccountAuthProvidersOptions struct {
	RequestID string
	PublicID  uuid.UUID
}

func (s *Services) ListAccountAuthProviders(
	ctx context.Context,
	opts ListAccountAuthProvidersOptions,
) ([]dtos.AuthProviderDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ListAccountAuthProviders").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Getting account auth providers...")

	providers, err := s.database.FindAccountAuthProvidersByAccountPublicId(ctx, opts.PublicID)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account auth providers", "error", err)
		return nil, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Retrieved account auth providers successfully")
	return utils.MapSlice(providers, dtos.MapAccountAuthProviderToDTO), nil
}

type GetAccountAuthProviderOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Provider  string
}

func (s *Services) GetAccountAuthProvider(
	ctx context.Context,
	opts GetAccountAuthProviderOptions,
) (dtos.AuthProviderDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "GetAccountAuthProvider").With(
		"publicID", opts.PublicID,
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Getting account auth provider...")

	provider, serviceErr := mapAuthProvider(opts.Provider)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Invalid auth provider", "serviceError", serviceErr)
		return dtos.AuthProviderDTO{}, serviceErr
	}

	authProvider, err := s.database.FindAccountAuthProviderByAccountPublicIdAndProvider(
		ctx,
		database.FindAccountAuthProviderByAccountPublicIdAndProviderParams{
			AccountPublicID: opts.PublicID,
			Provider:        provider,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get account auth provider", "error", err)
		return dtos.AuthProviderDTO{}, exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Retrieved account auth provider successfully")
	return dtos.MapAccountAuthProviderToDTO(&authProvider), nil
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

	totpKey, err := s.crypto.GenerateTotpKey(ctx, crypto.GenerateTotpKeyOptions{
		RequestID: opts.requestID,
		Email:     opts.email,
		GetDEKfn:  s.buildGetEncGlobalDEK(ctx, logger, opts.requestID),
		StoreTOTPfn: func(encSecret string, hashedCode []byte, url string) *exceptions.ServiceError {
			if err = qrs.CreateAccountTotps(ctx, database.CreateAccountTotpsParams{
				AccountID:     opts.id,
				Url:           url,
				Secret:        encSecret,
				RecoveryCodes: hashedCode,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to create account recovery keys", "error", err)
				serviceErr = exceptions.FromDBError(err)
				return serviceErr
			}

			return nil
		},
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate TOTP", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	account, err := qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
		TwoFactorType: database.TwoFactorTypeTotp,
		ID:            opts.id,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account 2FA", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}

	signedToken, err := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version,
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: opts.requestID,
			keyType:   database.TokenKeyType2faAuthentication,
			ttl:       s.jwt.Get2FATTL(),
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewAuthDTOWithData(
		signedToken,
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

		account, err = qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeEmail,
			ID:            opts.id,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to enable 2FA email", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		if err := qrs.DeleteAccountRecoveryKeys(ctx, opts.id); err != nil {
			logger.ErrorContext(ctx, "Failed to delete recovery keys", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		account, err = s.database.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeEmail,
			ID:            opts.id,
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

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version,
		}),
		GetJWKfn: s.buildEncryptedJWKFn(ctx, logger, buildEncryptedJWKFnOptions{
			requestID: opts.requestID,
			keyType:   database.TokenKeyType2faAuthentication,
			ttl:       s.jwt.Get2FATTL(),
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewTempAuthDTO(signedToken, "Please provide email two factor code", s.jwt.Get2FATTL()), nil
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

		account, err = qrs.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeNone,
			ID:            opts.id,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to disable 2FA", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}

		if err := qrs.DeleteAccountRecoveryKeys(ctx, opts.id); err != nil {
			logger.ErrorContext(ctx, "Failed to delete recovery keys", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return dtos.AuthDTO{}, serviceErr
		}
	} else {
		var err error
		account, err = s.database.UpdateAccountTwoFactorType(ctx, database.UpdateAccountTwoFactorTypeParams{
			TwoFactorType: database.TwoFactorTypeNone,
			ID:            opts.id,
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
		opts.requestID,
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
	logger := s.buildLogger(opts.RequestID, authLocation, "UpdateAccount2FA").With(
		"publicID", opts.PublicID,
		"twoFactorType", opts.TwoFactorType,
	)
	logger.InfoContext(ctx, "Updating account 2FA...")

	twoFactorType, serviceErr := mapTwoFactorType(opts.TwoFactorType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Invalid two factor type", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.PublicID,
		Version:   opts.Version,
	})
	if serviceErr != nil {
		return dtos.AuthDTO{}, serviceErr
	}

	count, err := s.database.CountAccountAuthProvidersByEmailAndProvider(
		ctx,
		database.CountAccountAuthProvidersByEmailAndProviderParams{
			Email:    accountDTO.Email,
			Provider: database.AuthProviderUsernamePassword,
		},
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to count auth providers", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if count > 0 {
		if opts.Password == "" {
			logger.WarnContext(ctx, "Password is required for email auth Provider")
			return dtos.AuthDTO{}, exceptions.NewValidationError("password is required")
		}

		ok, err := utils.Argon2CompareHash(opts.Password, accountDTO.Password())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to compare password hashes", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Passwords do not match")
			return dtos.AuthDTO{}, exceptions.NewValidationError("Invalid password")
		}
	}

	if accountDTO.TwoFactorType == twoFactorType {
		logger.WarnContext(ctx, "Account already uses given 2FA type", "twoFactorType", twoFactorType)
		return dtos.AuthDTO{}, exceptions.NewValidationError("Account already uses given 2FA type")
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

type ConfirmUpdateAccount2FAUpdateOptions struct {
	RequestID string
	PublicID  uuid.UUID
	Version   int32
	Code      string
}

func (s *Services) ConfirmUpdateAccount2FAUpdate(
	ctx context.Context,
	opts ConfirmUpdateAccount2FAUpdateOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ConfirmUpdateAccount2FAUpdate").With(
		"publicID", opts.PublicID,
	)
	logger.InfoContext(ctx, "Confirming account 2FA update...")

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
