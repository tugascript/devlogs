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
	"strconv"
	"time"

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
		logger.WarnContext(ctx, "Failed to extract token from auth header", "serviceError", serviceErr)
		return tokens.AccountClaims{}, nil, serviceErr
	}

	accountClaims, scopes, err := s.jwt.VerifyAccessToken(
		token,
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeAccess,
		}),
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify access token", "error", err)
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return accountClaims, scopes, nil
}

func (s *Services) Process2FAAuthHeader(
	ctx context.Context,
	opts ProcessAuthHeaderOptions,
) (tokens.AccountClaims, tokens.TwoFAType, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "Process2FAAuthHeader")
	logger.InfoContext(ctx, "Processing purpose auth header...")

	token, serviceErr := extractAuthHeaderToken(opts.AuthHeader)
	if serviceErr != nil {
		return tokens.AccountClaims{}, "", serviceErr
	}

	accountClaims, twoFAType, err := s.jwt.Verify2FAToken(
		token,
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyType2faAuthentication,
		}),
	)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify purpose token", "error", err)
		return tokens.AccountClaims{}, "", exceptions.NewUnauthorizedError()
	}

	return accountClaims, twoFAType, nil
}

func (s *Services) GetRefreshTTL() int64 {
	return s.jwt.GetRefreshTTL()
}

func (s *Services) Get2FATTL() int64 {
	return s.jwt.Get2FATTL()
}

func (s *Services) GetOAuthCodeTTL() int64 {
	return s.cache.OAuthCodeTTL()
}

func (s *Services) sendConfirmationEmail(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountDTO *dtos.AccountDTO,
) *exceptions.ServiceError {
	logger.InfoContext(ctx, "Sending confirmation email...")
	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token: s.jwt.CreateConfirmationToken(tokens.AccountConfirmationTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: requestID,
			KeyType:   database.TokenKeyTypeEmailVerification,
			TTL:       s.jwt.GetConfirmationTTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: requestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: requestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: requestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign confirmation token", "serviceError", serviceErr)
		return exceptions.NewInternalServerError()
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
		return exceptions.NewInternalServerError()
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
		Provider:   AuthProviderLocal,
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

func mapAccountScopes(scopes []tokens.AccountScope) ([]database.Scopes, []string) {
	dbScopes := make([]database.Scopes, 0)
	customScopes := make([]string, 0)

	for _, scope := range scopes {
		switch scope {
		case tokens.AccountScopeEmail:
			dbScopes = append(dbScopes, database.ScopesEmail)
		case tokens.AccountScopeProfile:
			dbScopes = append(dbScopes, database.ScopesProfile)
		default:
			customScopes = append(customScopes, scope)
		}
	}

	return dbScopes, customScopes
}

func validateScopes(
	scopes []tokens.AccountScope,
	grantedScopes []database.Scopes,
	grantedCustomScopes []string,
) *exceptions.ServiceError {
	scopesSet := utils.SliceToHashSet(scopes)

	for _, grantedScope := range grantedScopes {
		if !scopesSet.Contains(tokens.AccountScope(grantedScope)) {
			return exceptions.NewForbiddenError()
		}
	}

	for _, grantedCustomScope := range grantedCustomScopes {
		if !scopesSet.Contains(grantedCustomScope) {
			return exceptions.NewForbiddenError()
		}
	}

	return nil
}

type upsertAccountGrantSessionAndTokenOptions struct {
	requestID       string
	accountID       int32
	accountVersion  int32
	accountPublicID uuid.UUID
	scopes          []tokens.AccountScope
	sessionID       uuid.UUID
	tokenID         uuid.UUID
	clientID        utils.Base62UUIDStr
	ipAddress       string
	userAgent       string
}

func (s *Services) createAccountGrantSessionAndToken(
	ctx context.Context,
	opts upsertAccountGrantSessionAndTokenOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, authLocation, "createAccountGrantSessionAndToken").With(
		"accountID", opts.accountID,
		"accountVersion", opts.accountVersion,
		"accountPublicID", opts.accountPublicID,
		"sessionID", opts.sessionID,
		"clientID", opts.clientID,
	)
	logger.InfoContext(ctx, "Creating account grant session and token...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientIDAndAccountPublicID(ctx, GetAccountCredentialsByClientIDAndAccountPublicIDOptions{
		RequestID:       opts.requestID,
		AccountPublicID: opts.accountPublicID,
		ClientID:        opts.clientID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account credentials", "error", serviceErr)
			return serviceErr
		}
		serviceErr = nil
	}

	grantUUID, err := uuid.NewV7()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate grant UUID", "error", err)
		return exceptions.NewInternalServerError()
	}

	grantedScopes, grantedCustomScopes := mapAccountScopes(opts.scopes)
	expiresAt := time.Now().Add(time.Duration(s.jwt.GetRefreshTTL()) * time.Second)
	var ipAddress pgtype.Text
	if err := ipAddress.Scan(opts.ipAddress); err != nil {
		logger.ErrorContext(ctx, "Failed to scan IP address", "error", err)
		return exceptions.NewInternalServerError()
	}

	var userAgent pgtype.Text
	if err := userAgent.Scan(opts.userAgent); err != nil {
		logger.ErrorContext(ctx, "Failed to scan user agent", "error", err)
		return exceptions.NewInternalServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	grantID, err := qrs.CreateGrant(ctx, database.CreateGrantParams{
		AccountID:           opts.accountID,
		GrantID:             grantUUID,
		GrantedClientID:     opts.clientID,
		GrantedScopes:       grantedScopes,
		GrantedCustomScopes: grantedCustomScopes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create grant", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	sessionID, err := qrs.CreateSession(ctx, database.CreateSessionParams{
		AccountID:       opts.accountID,
		GrantID:         grantID,
		SessionID:       opts.sessionID,
		SessionType:     database.SessionTypeSliding,
		SessionClientID: opts.clientID,
		IpAddress:       ipAddress,
		UserAgent:       userAgent,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create session", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	if accountCredentialsDTO.ID() > 0 {
		var accountCredentialsID pgtype.Int4
		if err = accountCredentialsID.Scan(accountCredentialsDTO.ID()); err != nil {
			logger.ErrorContext(ctx, "Failed to scan account credentials ID", "error", err)
			return exceptions.NewInternalServerError()
		}

		if err = qrs.CreateAccountSessionWithAccountCredentials(ctx, database.CreateAccountSessionWithAccountCredentialsParams{
			AccountID:            opts.accountID,
			AccountVersion:       opts.accountVersion,
			AccountCredentialsID: accountCredentialsID,
			SessionID:            sessionID,
			SessionUuid:          opts.sessionID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account session with account credentials", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}
	} else {
		if err = qrs.CreateAccountSessionWithoutAccountCredentials(ctx, database.CreateAccountSessionWithoutAccountCredentialsParams{
			AccountID:      opts.accountID,
			AccountVersion: opts.accountVersion,
			SessionID:      sessionID,
			SessionUuid:    opts.sessionID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account session without account credentials", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}
	}

	if err = qrs.CreateSessionToken(ctx, database.CreateSessionTokenParams{
		SessionID:   sessionID,
		SessionUuid: opts.sessionID,
		TokenID:     opts.tokenID,
		AccountID:   opts.accountID,
		GrantID:     grantID,
		ExpiresAt:   expiresAt,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create session token", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	logger.InfoContext(ctx, "Created account grant, session and token successfully")
	return nil
}

type createAccountSessionAndTokenOptions struct {
	requestID       string
	accountID       int32
	accountVersion  int32
	accountPublicID uuid.UUID
	scopes          []tokens.AccountScope
	sessionID       uuid.UUID
	tokenID         uuid.UUID
	clientID        utils.Base62UUIDStr
	ipAddress       string
	userAgent       string
	grantID         int32
}

func (s *Services) createAccountSessionAndToken(
	ctx context.Context,
	opts createAccountSessionAndTokenOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, authLocation, "createAccountSessionAndToken").With(
		"accountID", opts.accountID,
		"accountVersion", opts.accountVersion,
		"accountPublicID", opts.accountPublicID,
		"sessionID", opts.sessionID,
		"clientID", opts.clientID,
	)
	logger.InfoContext(ctx, "Creating account session and token...")

	accountCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientIDAndAccountPublicID(ctx, GetAccountCredentialsByClientIDAndAccountPublicIDOptions{
		RequestID:       opts.requestID,
		AccountPublicID: opts.accountPublicID,
		ClientID:        opts.clientID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account credentials", "error", serviceErr)
			return serviceErr
		}
		serviceErr = nil
	}

	expiresAt := time.Now().Add(time.Duration(s.jwt.GetRefreshTTL()) * time.Second)
	var ipAddress pgtype.Text
	if err := ipAddress.Scan(opts.ipAddress); err != nil {
		logger.ErrorContext(ctx, "Failed to scan IP address", "error", err)
		return exceptions.NewInternalServerError()
	}

	var userAgent pgtype.Text
	if err := userAgent.Scan(opts.userAgent); err != nil {
		logger.ErrorContext(ctx, "Failed to scan user agent", "error", err)
		return exceptions.NewInternalServerError()
	}

	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	sessionID, err := qrs.CreateSession(ctx, database.CreateSessionParams{
		AccountID:       opts.accountID,
		GrantID:         opts.grantID,
		SessionID:       opts.sessionID,
		SessionType:     database.SessionTypeSliding,
		SessionClientID: opts.clientID,
		IpAddress:       ipAddress,
		UserAgent:       userAgent,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create session", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	if accountCredentialsDTO.ID() > 0 {
		var accountCredentialsID pgtype.Int4
		if err = accountCredentialsID.Scan(accountCredentialsDTO.ID()); err != nil {
			logger.ErrorContext(ctx, "Failed to scan account credentials ID", "error", err)
			return exceptions.NewInternalServerError()
		}

		if err = qrs.CreateAccountSessionWithAccountCredentials(ctx, database.CreateAccountSessionWithAccountCredentialsParams{
			AccountID:            opts.accountID,
			AccountVersion:       opts.accountVersion,
			AccountCredentialsID: accountCredentialsID,
			SessionID:            sessionID,
			SessionUuid:          opts.sessionID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account session with account credentials", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}
	} else {
		if err = qrs.CreateAccountSessionWithoutAccountCredentials(ctx, database.CreateAccountSessionWithoutAccountCredentialsParams{
			AccountID:      opts.accountID,
			AccountVersion: opts.accountVersion,
			SessionID:      sessionID,
			SessionUuid:    opts.sessionID,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to create account session without account credentials", "error", err)
			serviceErr = exceptions.FromDBError(err)
			return serviceErr
		}
	}

	if err = qrs.CreateSessionToken(ctx, database.CreateSessionTokenParams{
		SessionID:   sessionID,
		SessionUuid: opts.sessionID,
		TokenID:     opts.tokenID,
		AccountID:   opts.accountID,
		GrantID:     opts.grantID,
		ExpiresAt:   expiresAt,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create session token", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	logger.InfoContext(ctx, "Created account session and token successfully")
	return nil
}

func (s *Services) upsertAccountGrantSessionAndToken(
	ctx context.Context,
	opts upsertAccountGrantSessionAndTokenOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, authLocation, "upsertAccountGrantSessionAndToken").With(
		"accountID", opts.accountID,
		"accountVersion", opts.accountVersion,
		"accountPublicID", opts.accountPublicID,
		"sessionID", opts.sessionID,
		"clientID", opts.clientID,
	)
	logger.InfoContext(ctx, "Upserting account grant session and token...")

	grant, err := s.database.FindAccountGrantByAccountIDAndGrantedClientID(ctx, database.FindAccountGrantByAccountIDAndGrantedClientIDParams{
		AccountID:       opts.accountID,
		GrantedClientID: opts.clientID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch grant", "error", err)
			return serviceErr
		}

		return s.createAccountGrantSessionAndToken(ctx, opts)
	}

	session, err := s.database.FindAccountSessionByAccountIDAndSessionUUID(ctx, database.FindAccountSessionByAccountIDAndSessionUUIDParams{
		AccountID:   opts.accountID,
		SessionUuid: opts.sessionID,
	})
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch account session", "error", err)
			return serviceErr
		}

		return s.createAccountSessionAndToken(ctx, createAccountSessionAndTokenOptions{
			requestID:       opts.requestID,
			accountID:       opts.accountID,
			accountVersion:  opts.accountVersion,
			accountPublicID: opts.accountPublicID,
			scopes:          opts.scopes,
			sessionID:       opts.sessionID,
			tokenID:         opts.tokenID,
			clientID:        opts.clientID,
			ipAddress:       opts.ipAddress,
			userAgent:       opts.userAgent,
			grantID:         grant.GrantID,
		})
	}

	expiresAt := time.Now().Add(time.Duration(s.jwt.GetRefreshTTL()) * time.Second)
	var serviceErr *exceptions.ServiceError
	qrs, txn, err := s.database.BeginTx(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to start transaction", "error", err)
		return exceptions.FromDBError(err)
	}
	defer func() {
		logger.DebugContext(ctx, "Finalizing transaction")
		s.database.FinalizeTx(ctx, txn, err, serviceErr)
	}()

	if err = qrs.UpdateSessionExpiresAt(ctx, database.UpdateSessionExpiresAtParams{
		ExpiresAt: expiresAt,
		ID:        session.SessionID,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to update session expires at", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	if err = qrs.CreateSessionToken(ctx, database.CreateSessionTokenParams{
		SessionID:   session.SessionID,
		SessionUuid: opts.sessionID,
		TokenID:     opts.tokenID,
		AccountID:   opts.accountID,
		GrantID:     grant.GrantID,
		ExpiresAt:   expiresAt,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create session token", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return serviceErr
	}

	logger.InfoContext(ctx, "Upserted account grant session and token successfully")
	return nil
}

type generateFullAuthDTOOptions struct {
	requestID       string
	accountID       int32
	accountPublicID uuid.UUID
	accountVersion  int32
	sessionID       uuid.UUID
	ipAddress       string
	userAgent       string
	clientID        utils.Base62UUIDStr
	scopes          []tokens.AccountScope
}

func (s *Services) generateFullAuthDTO(
	ctx context.Context,
	opts generateFullAuthDTOOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, authLocation, "generateFullAuthDTO").With(
		"accountID", opts.accountID,
		"accountPublicID", opts.accountPublicID,
		"accountVersion", opts.accountVersion,
		"sessionID", opts.sessionID,
		"scopes", opts.scopes,
	)
	logger.InfoContext(ctx, "Generating full auth DTO...")

	accessToken, err := s.jwt.CreateAccessToken(tokens.AccountAccessTokenOptions{
		PublicID:     opts.accountPublicID,
		Version:      opts.accountVersion,
		Scopes:       opts.scopes,
		TokenSubject: opts.accountPublicID.String(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	accessTTL := s.jwt.GetAccessTTL()
	signedAccessToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token:     accessToken,
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyTypeAccess,
			TTL:       accessTTL,
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.requestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign access token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	refreshToken, refreshJTI, err := s.jwt.CreateRefreshToken(tokens.AccountRefreshTokenOptions{
		PublicID: opts.accountPublicID,
		Version:  opts.accountVersion,
		Scopes:   opts.scopes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	refreshTTL := s.jwt.GetRefreshTTL()
	signedRefreshToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.requestID,
		Token:     refreshToken,
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.requestID,
			KeyType:   database.TokenKeyTypeRefresh,
			TTL:       refreshTTL,
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: opts.requestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: opts.requestID,
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to sign refresh token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	if serviceErr := s.upsertAccountGrantSessionAndToken(ctx, upsertAccountGrantSessionAndTokenOptions{
		requestID:       opts.requestID,
		accountID:       opts.accountID,
		accountVersion:  opts.accountVersion,
		accountPublicID: opts.accountPublicID,
		scopes:          opts.scopes,
		sessionID:       opts.sessionID,
		tokenID:         refreshJTI,
		clientID:        opts.clientID,
		ipAddress:       opts.ipAddress,
		userAgent:       opts.userAgent,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to upsert account grant session and token", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	logger.InfoContext(ctx, "Generated full auth DTO successfully")
	return dtos.NewFullAuthDTO(signedAccessToken, signedRefreshToken, accessTTL), nil
}

type ConfirmAccountOptions struct {
	RequestID         string
	ConfirmationToken string
	IPAddress         string
	UserAgent         string
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
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeEmailVerification,
		}),
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

	sessionID, err := uuid.NewV7()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate session ID", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	return s.generateFullAuthDTO(
		ctx,
		generateFullAuthDTOOptions{
			requestID:       opts.RequestID,
			accountID:       accountDTO.ID(),
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			sessionID:       sessionID,
			scopes:          []tokens.AccountScope{tokens.AccountScopeAdmin},
			clientID:        utils.NilBase62UUID,
			ipAddress:       opts.IPAddress,
			userAgent:       opts.UserAgent,
		},
	)
}

func (s *Services) generate2FAAuth(
	ctx context.Context,
	logger *slog.Logger,
	requestID string,
	accountDTO *dtos.AccountDTO,
	twoFAType database.TwoFactorType,
	msg string,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	twoFAToken, err := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID:  accountDTO.PublicID,
			Version:   accountDTO.Version(),
			TwoFAType: tokens.TwoFAType(twoFAType),
		}),
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: requestID,
			KeyType:   database.TokenKeyType2faAuthentication,
			TTL:       s.jwt.Get2FATTL(),
		}),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: requestID,
		}),
		GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
			RequestID: requestID,
		}),
		StoreFN: s.BuildUpdateJWKDEKFn(ctx, BuildUpdateJWKDEKFnOptions{
			RequestID: requestID,
		}),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to sign 2FA token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	if twoFAType == database.TwoFactorTypeEmail {
		code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
			RequestID: requestID,
			AccountID: accountDTO.ID(),
			TTL:       s.jwt.Get2FATTL(),
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate two factor Code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewInternalServerError()
		}

		if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
			RequestID: requestID,
			Email:     accountDTO.Email,
			Name:      fmt.Sprintf("%s %s", accountDTO.GivenName, accountDTO.FamilyName),
			Code:      code,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
			return dtos.AuthDTO{}, exceptions.NewInternalServerError()
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
	IPAddress string
	UserAgent string
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
	if _, err := s.database.FindAccountAuthProviderByAccountPublicIdAndProvider(
		ctx,
		database.FindAccountAuthProviderByAccountPublicIdAndProviderParams{
			AccountPublicID: accountDTO.PublicID,
			Provider:        database.AuthProviderLocal,
		},
	); err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find account auth provider", "error", err)
			return dtos.AuthDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account auth provider not found", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	passwordVerified, err := utils.Argon2CompareHash(opts.Password, accountDTO.Password())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify password", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
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

	default2FaConfig, serviceErr := s.getDefaultAccount2FAConfigInternal(ctx, getDefaultAccount2FAConfigInternalOptions{
		requestID:       opts.RequestID,
		accountPublicID: accountDTO.PublicID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get default account 2FA config", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}
	if default2FaConfig != nil {
		authDTO, serviceErr := s.generate2FAAuth(
			ctx,
			logger,
			opts.RequestID,
			&accountDTO,
			default2FaConfig.TwoFactorType,
			"Please provide two factor code",
		)
		if serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
		return authDTO, nil
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate session ID", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	return s.generateFullAuthDTO(
		ctx,
		generateFullAuthDTOOptions{
			requestID:       opts.RequestID,
			accountID:       accountDTO.ID(),
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			sessionID:       sessionID,
			scopes:          []tokens.AccountScope{tokens.AccountScopeAdmin},
			clientID:        utils.NilBase62UUID,
			ipAddress:       opts.IPAddress,
			userAgent:       opts.UserAgent,
		},
	)
}

func (s *Services) buildGetAccountTOTPFn(
	ctx context.Context,
	requestID string,
) crypto.GetTOTPSecret {
	logger := s.buildLogger(requestID, authLocation, "buildGetAccountTOTPFn")
	logger.InfoContext(ctx, "Building GetAccountTOTP function...")

	return func(ownerID int32) (crypto.DEKCiphertext, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting TOTP secret...")
		accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, ownerID)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code == exceptions.CodeNotFound {
				logger.WarnContext(ctx, "Account TOTP not found", "error", err)
				return "", exceptions.NewForbiddenError()
			}

			logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
			return "", serviceErr
		}

		logger.InfoContext(ctx, "Found account TOTP secret")
		return accountTOTP.Secret, nil
	}
}

func (s *Services) buildUpdateAccountTOTPDEKFn(
	ctx context.Context,
	requestID string,
) crypto.StoreReEncryptedData {
	logger := s.buildLogger(requestID, authLocation, "buildUpdateAccountTOTPDEKFn")
	logger.InfoContext(ctx, "Building UpdateAccountTOTPDEK function...")

	return func(
		accountID crypto.EntityID,
		dekID crypto.DEKID,
		secret crypto.DEKCiphertext,
	) *exceptions.ServiceError {
		logger.InfoContext(ctx, "Updating TOTP secret...")
		intID, err := strconv.ParseInt(accountID, 10, 32)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to parse account ID", "error", err)
			return exceptions.NewInternalServerError()
		}

		accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, int32(intID))
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
			return exceptions.FromDBError(err)
		}

		if err := s.database.UpdateTOTPSecretAndDEK(ctx, database.UpdateTOTPSecretAndDEKParams{
			ID:     accountTOTP.ID,
			DekKid: dekID,
			Secret: secret,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update TOTP secret", "error", err)
			return exceptions.FromDBError(err)
		}

		logger.InfoContext(ctx, "Updated TOTP secret successfully")
		return nil
	}
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
		GetSecret: s.buildGetAccountTOTPFn(ctx, opts.RequestID),
		GetDecryptDEKFN: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
			RequestID: opts.RequestID,
			AccountID: opts.ID,
		}),
		GetEncryptDEKFN: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.RequestID,
			AccountID: opts.ID,
		}),
		StoreFN: s.buildUpdateAccountTOTPDEKFn(ctx, opts.RequestID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP Code", "error", serviceErr)
		return false, serviceErr
	}

	return verified, nil
}

func mapTokens2FAType(twoFAType tokens.TwoFAType) (database.TwoFactorType, *exceptions.ServiceError) {
	switch twoFAType {
	case tokens.TwoFATypeTOTP:
		return database.TwoFactorTypeTotp, nil
	case tokens.TwoFATypeEmail:
		return database.TwoFactorTypeEmail, nil
	default:
		return "", exceptions.NewUnauthorizedError()
	}
}

type verifyAccount2FAInternalOptions struct {
	requestID       string
	accountID       int32
	accountPublicID uuid.UUID
	accountVersion  int32
	twoFAType       tokens.TwoFAType
	code            string
}

func (s *Services) verifyAccount2FAInternal(
	ctx context.Context,
	opts verifyAccount2FAInternalOptions,
) *exceptions.ServiceError {
	logger := s.buildLogger(opts.requestID, authLocation, "verifyDefaultAccount2FA").With(
		"accountPublicId", opts.accountPublicID,
	)
	logger.InfoContext(ctx, "Verifying account two factor...")

	twoFAType, serviceErr := mapTokens2FAType(opts.twoFAType)
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to map two factor type", "serviceError", serviceErr)
		return serviceErr
	}

	configDTO, serviceErr := s.GetAccount2FAConfig(ctx, GetAccount2FAConfigOptions{
		RequestID:       opts.requestID,
		AccountPublicID: opts.accountPublicID,
		TwoFAType:       twoFAType,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account 2FA config not found", "serviceError", serviceErr)
			return exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get account 2FA config", "serviceError", serviceErr)
		return serviceErr
	}

	switch configDTO.TwoFactorType {
	case database.TwoFactorTypeTotp:
		ok, serviceErr := s.VerifyAccountTotp(ctx, VerifyAccountTotpOptions{
			RequestID: opts.requestID,
			ID:        opts.accountID,
			Code:      opts.code,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP Code", "serviceError", serviceErr)
			return serviceErr
		}
		if !ok {
			logger.WarnContext(ctx, "Failed to verify TOTP Code")
			return exceptions.NewUnauthorizedError()
		}
	case database.TwoFactorTypeEmail:
		ok, err := s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.requestID,
			AccountID: opts.accountID,
			Code:      opts.code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Error verifying Code", "error", err)
			return exceptions.NewInternalServerError()
		}
		if !ok {
			logger.WarnContext(ctx, "Failed to verify Code")
			return exceptions.NewUnauthorizedError()
		}
	default:
		logger.WarnContext(ctx, "Invalid two factor type", "twoFactorType", configDTO.TwoFactorType)
		return exceptions.NewUnauthorizedError()
	}

	logger.InfoContext(ctx, "Account two factor verified successfully")
	return nil
}

type VerifyAccount2FAOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	AccountVersion  int32
	TwoFAType       tokens.TwoFAType
	Code            string
	IPAddress       string
	UserAgent       string
}

func (s *Services) VerifyAccount2FA(
	ctx context.Context,
	opts VerifyAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "VerifyAccount2FA").With(
		"accountPublicId", opts.AccountPublicID,
		"twoFactorType", opts.TwoFAType,
	)
	logger.InfoContext(ctx, "Verifying account two factor...")

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
		Version:   opts.AccountVersion,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account ID by public ID and version", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if serviceErr := s.verifyAccount2FAInternal(ctx, verifyAccount2FAInternalOptions{
		requestID:       opts.RequestID,
		accountID:       accountDTO.ID(),
		accountPublicID: opts.AccountPublicID,
		accountVersion:  opts.AccountVersion,
		twoFAType:       opts.TwoFAType,
		code:            opts.Code,
	}); serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to verify account two factor", "serviceError", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate session ID", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	return s.generateFullAuthDTO(
		ctx,
		generateFullAuthDTOOptions{
			requestID:       opts.RequestID,
			accountID:       accountDTO.ID(),
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			sessionID:       sessionID,
			scopes:          []tokens.AccountScope{tokens.AccountScopeAdmin},
			clientID:        utils.NilBase62UUID,
			ipAddress:       opts.IPAddress,
			userAgent:       opts.UserAgent,
		},
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

	data, err := s.jwt.VerifyRefreshToken(
		opts.RefreshToken,
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeRefresh,
		}),
	)
	if err != nil {
		logger.WarnContext(ctx, "Failed to verify refresh token", "error", err)
		return exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountClaims.AccountID,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to find account of refresh token")
		return exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if accountVersion != data.AccountClaims.AccountVersion {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", data.AccountClaims.AccountVersion,
			"accountVersion", accountVersion,
		)
		return exceptions.NewUnauthorizedError()
	}

	sessionToken, err := s.database.FindSessionTokenByTokenID(ctx, data.TokenID)
	if err != nil {
		serviceErr = exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch session token", "error", err)
			return exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Session token was not found in the DB, it is probably revoked")
		return exceptions.NewUnauthorizedError()
	}
	if sessionToken.ExpiresAt.Before(time.Now()) {
		logger.WarnContext(ctx, "Session token is expired")
		return exceptions.NewUnauthorizedError()
	}

	accountSession, err := s.database.FindAccountSessionByAccountIDAndSessionUUID(
		ctx,
		database.FindAccountSessionByAccountIDAndSessionUUIDParams{
			AccountID:   accountDTO.ID(),
			SessionUuid: sessionToken.SessionUuid,
		},
	)
	if err != nil {
		serviceErr = exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch account session", "error", err)
			return exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Account session was not found in the DB")
		return exceptions.NewUnauthorizedError()
	}

	if err := s.database.DeleteSessionByID(ctx, accountSession.SessionID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete session", "error", err)
		return exceptions.FromDBError(err)
	}

	logger.InfoContext(ctx, "Logged out account successfully")
	return nil
}

type RefreshTokenAccountOptions struct {
	RequestID    string
	RefreshToken string
	IPAddress    string
	UserAgent    string
}

func (s *Services) RefreshTokenAccount(
	ctx context.Context,
	opts RefreshTokenAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "RefreshTokenAccount")
	logger.InfoContext(ctx, "Refreshing account access token...")

	data, err := s.jwt.VerifyRefreshToken(
		opts.RefreshToken,
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypeRefresh,
		}),
	)
	if err != nil {
		logger.WarnContext(ctx, "Invalid refresh token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	sessionToken, err := s.database.FindSessionTokenByTokenID(ctx, data.TokenID)
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to fetch session token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Token was not found in the DB, it is probably revoked")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}
	if sessionToken.ExpiresAt.Before(time.Now()) {
		if err := s.database.DeleteSessionToken(ctx, data.TokenID); err != nil {
			logger.ErrorContext(ctx, "Failed to delete session token", "error", err)
			return dtos.AuthDTO{}, exceptions.NewInternalServerError()
		}

		logger.WarnContext(ctx, "Session token is expired")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByPublicIDAndVersion(ctx, GetAccountByPublicIDAndVersionOptions{
		RequestID: opts.RequestID,
		PublicID:  data.AccountClaims.AccountID,
		Version:   data.AccountClaims.AccountVersion,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by public ID and version", "serviceErr", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	if err := s.database.DeleteSessionToken(ctx, data.TokenID); err != nil {
		logger.ErrorContext(ctx, "Failed to delete session token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate session ID", "error", err)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}

	return s.generateFullAuthDTO(
		ctx,
		generateFullAuthDTOOptions{
			requestID:       opts.RequestID,
			accountID:       accountDTO.ID(),
			accountPublicID: accountDTO.PublicID,
			accountVersion:  accountDTO.Version(),
			sessionID:       sessionID,
			scopes:          data.Scopes,
			clientID:        utils.NilBase62UUID,
			ipAddress:       opts.IPAddress,
			userAgent:       opts.UserAgent,
		},
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
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(ctx, BuildEncryptedJWKFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypePasswordReset,
			TTL:       s.jwt.GetResetTTL(),
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
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate rest token", "error", err)
		return dtos.MessageDTO{}, exceptions.NewInternalServerError()
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
		return dtos.MessageDTO{}, exceptions.NewInternalServerError()
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
		s.BuildGetGlobalPublicKeyFn(ctx, BuildGetGlobalVerifyKeyFnOptions{
			RequestID: opts.RequestID,
			KeyType:   database.TokenKeyTypePasswordReset,
		}),
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
		return dtos.MessageDTO{}, exceptions.NewInternalServerError()
	}

	if err := password.Scan(hashedPassword); err != nil {
		logger.ErrorContext(ctx, "Failed pass password to text", "error", err)
		return dtos.MessageDTO{}, exceptions.NewInternalServerError()
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

func (s *Services) buildGetAccountRecoveryCodesFn(
	ctx context.Context,
	requestID string,
) crypto.GetTOTPRecoveryCodes {
	logger := s.buildLogger(requestID, authLocation, "buildGetAccountRecoveryCodesFn")
	logger.InfoContext(ctx, "Building GetAccountRecoveryCodes function...")

	return func(ownerID int32) ([]byte, *exceptions.ServiceError) {
		logger.InfoContext(ctx, "Getting recovery codes...")
		accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, ownerID)
		if err != nil {
			serviceErr := exceptions.FromDBError(err)
			if serviceErr.Code == exceptions.CodeNotFound {
				logger.WarnContext(ctx, "Account TOTP not found", "error", err)
				return nil, exceptions.NewForbiddenError()
			}

			logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
			return nil, serviceErr
		}

		logger.InfoContext(ctx, "Found account recovery codes")
		return accountTOTP.RecoveryCodes, nil
	}
}

type buildUpdateAccountTOTPFnOptions struct {
	requestID string
	accountID int32
}

func (s *Services) buildUpdateAccountTOTPFn(
	ctx context.Context,
	opts buildUpdateAccountTOTPFnOptions,
) crypto.StoreTOTP {
	logger := s.buildLogger(opts.requestID, authLocation, "buildUpdateAccountTOTPFn")
	logger.InfoContext(ctx, "Building update account TOTP function...")

	return func(dekKID, encSecret string, hashedCode []byte, url string) *exceptions.ServiceError {
		logger.InfoContext(ctx, "Updating account TOTP...")
		accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, opts.accountID)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
			return exceptions.FromDBError(err)
		}

		if err := s.database.UpdateTOTP(ctx, database.UpdateTOTPParams{
			ID:            accountTOTP.ID,
			DekKid:        dekKID,
			Secret:        encSecret,
			RecoveryCodes: hashedCode,
			Url:           url,
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account TOTP", "error", err)
			return exceptions.FromDBError(err)
		}

		return nil
	}
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
	if _, serviceErr := s.GetAccount2FAConfig(ctx, GetAccount2FAConfigOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: accountDTO.PublicID,
		TwoFAType:       database.TwoFactorTypeTotp,
	}); serviceErr != nil {
		logger.WarnContext(ctx, "Account does not have TOTP enabled", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	ok, newTotpKey, serviceErr := s.crypto.VerifyTotpRecoveryCode(ctx, crypto.VerifyTotpRecoveryCodeOptions{
		RequestID:    opts.RequestID,
		Email:        accountDTO.Email,
		RecoveryCode: opts.RecoveryCode,
		OwnerID:      accountDTO.ID(),
		GetCodes:     s.buildGetAccountRecoveryCodesFn(ctx, opts.RequestID),
		GetDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID(),
		}),
		StoreTOTPfn: s.buildUpdateAccountTOTPFn(ctx, buildUpdateAccountTOTPFnOptions{
			requestID: opts.RequestID,
			accountID: accountDTO.ID(),
		}),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP recovery code", "serviceError", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Failed to verify TOTP recovery code")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	signedToken, serviceErr := s.crypto.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: opts.RequestID,
		Token: s.jwt.Create2FAToken(tokens.Account2FATokenOptions{
			PublicID:  accountDTO.PublicID,
			Version:   accountDTO.Version(),
			TwoFAType: tokens.TwoFATypeTOTP,
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
		return dtos.AuthDTO{}, exceptions.NewInternalServerError()
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
