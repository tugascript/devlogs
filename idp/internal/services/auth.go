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
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const authLocation string = "auth"

func processAuthHeader(
	authHeader string,
	verify func(string) (tokens.AccountClaims, []tokens.AccountScope, error),
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	authHeaderSlice := strings.Split(authHeader, " ")

	if len(authHeaderSlice) != 2 {
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}
	if utils.Lowered(authHeaderSlice[0]) != "bearer" {
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	accountClaims, scopes, err := verify(authHeaderSlice[1])
	if err != nil {
		return tokens.AccountClaims{}, nil, exceptions.NewUnauthorizedError()
	}

	return accountClaims, scopes, nil
}

func (s *Services) ProcessAccountAuthHeader(
	authHeader string,
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	return processAuthHeader(authHeader, s.jwt.VerifyAccessToken)
}

func (s *Services) Process2FAAuthHeader(
	authHeader string,
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	return processAuthHeader(authHeader, s.jwt.Verify2FAToken)
}

func (s *Services) ProcessOAuthHeader(
	authHeader string,
) (tokens.AccountClaims, []tokens.AccountScope, *exceptions.ServiceError) {
	return processAuthHeader(authHeader, s.jwt.VerifyOAuthToken)
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
	confirmationToken, err := s.jwt.CreateConfirmationToken(tokens.AccountTokenOptions{
		ID:      accountDTO.ID,
		Version: accountDTO.Version(),
		Email:   accountDTO.Email,
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
			utils.Capitalized(accountDTO.FirstName),
			utils.Capitalized(accountDTO.LastName),
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
	FirstName string
	LastName  string
	Password  string
}

func (s *Services) RegisterAccount(
	ctx context.Context,
	opts RegisterAccountOptions,
) (dtos.MessageDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "RegisterAccount").With(
		"firstName", opts.FirstName,
		"lastName", opts.LastName,
	)
	logger.InfoContext(ctx, "Registering account...")

	accountDTO, serviceErr := s.CreateAccount(ctx, CreateAccountOptions{
		RequestID: opts.RequestID,
		FirstName: opts.FirstName,
		LastName:  opts.LastName,
		Email:     opts.Email,
		Password:  opts.Password,
		Provider:  AuthProviderEmail,
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
	tokenOpts := tokens.AccountTokenOptions{
		ID:      accountDTO.ID,
		Version: accountDTO.Version(),
		Email:   accountDTO.Email,
		Scopes:  scopes,
	}
	accessToken, err := s.jwt.CreateAccessToken(tokenOpts)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	refreshToken, err := s.jwt.CreateRefreshToken(tokenOpts)
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

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        int32(claims.ID),
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by token AccountID", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if claims.Version != accountVersion {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.Version,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	if accountDTO.IsConfirmed() {
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

	if !accountDTO.IsConfirmed() {
		logger.InfoContext(ctx, "User is not confirmed, sending new confirmation email")

		if serviceErr := s.sendConfirmationEmail(ctx, logger, opts.RequestID, &accountDTO); serviceErr != nil {
			return dtos.AuthDTO{}, serviceErr
		}
	}

	switch accountDTO.TwoFactorType {
	case TwoFactorEmail, TwoFactorTotp:
		twoFAToken, err := s.jwt.Create2FAToken(tokens.AccountTokenOptions{
			ID:      accountDTO.ID,
			Version: accountDTO.Version(),
			Email:   accountDTO.Email,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Failed to generate 2FA JWT", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}

		if accountDTO.TwoFactorType == TwoFactorEmail {
			code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
				RequestID: opts.RequestID,
				AccountID: accountDTO.ID,
			})
			if err != nil {
				logger.ErrorContext(ctx, "Failed to generate two factor code", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}

			if err := s.mail.Publish2FAEmail(ctx, mailer.TwoFactorEmailOptions{
				RequestID: opts.RequestID,
				Email:     opts.Email,
				Name:      fmt.Sprintf("%s %s", accountDTO.FirstName, accountDTO.LastName),
				Code:      code,
			}); err != nil {
				logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
				return dtos.AuthDTO{}, exceptions.NewServerError()
			}
		}

		return dtos.NewTempAuthDTO(
			twoFAToken,
			"Please provide two factor code",
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
}

func (s *Services) VerifyAccountTotp(
	ctx context.Context,
	opts VerifyAccountTotpOptions,
) (bool, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "VerifyAccountTotp").With(
		"id", opts.ID,
	)
	logger.InfoContext(ctx, "Verifying account TOTP...")

	accountTOTP, err := s.database.FindAccountTotpByAccountID(ctx, int32(opts.ID))
	if err != nil {
		serviceErr := exceptions.FromDBError(err)
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account TOTP not found", "error", err)
			return false, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to find account TOTP", "error", err)
		return false, serviceErr
	}

	ok, newDEK, err := s.encrypt.VerifyAccountTotpCode(ctx, encryption.VerifyAccountTotpCodeOptions{
		RequestID:       opts.RequestID,
		EncryptedSecret: accountTOTP.Secret,
		StoredDEK:       accountTOTP.Dek,
		Code:            opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", err)
		return false, exceptions.NewServerError()
	}

	if newDEK != "" {
		logger.InfoContext(ctx, "Saving new DEK")
		if err := s.database.UpdateAccountTotpByAccountID(ctx, database.UpdateAccountTotpByAccountIDParams{
			Dek:       newDEK,
			AccountID: int32(opts.ID),
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to update account TOTP DEK", "error", err)
			return false, exceptions.FromDBError(err)
		}
	}

	return ok, nil
}

type TwoFactorLoginAccountOptions struct {
	RequestID string
	ID        int32
	Version   int
	Code      string
}

func (s *Services) TwoFactorLoginAccount(
	ctx context.Context,
	opts TwoFactorLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "TwoFactorLoginAccount")
	logger.InfoContext(ctx, "2FA logging in account...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	logger = logger.With("accountId", accountDTO.ID)
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
			ID:        opts.ID,
			Code:      opts.Code,
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to verify TOTP code", "error", serviceErr)
			return dtos.AuthDTO{}, serviceErr
		}
	case TwoFactorEmail:
		ok, err = s.cache.VerifyTwoFactorCode(ctx, cache.VerifyTwoFactorCodeOptions{
			RequestID: opts.RequestID,
			AccountID: accountDTO.ID,
			Code:      opts.Code,
		})
		if err != nil {
			logger.ErrorContext(ctx, "Error verifying code", "error", err)
			return dtos.AuthDTO{}, exceptions.NewServerError()
		}
	}

	if !ok {
		logger.WarnContext(ctx, "Failed to verify code")
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

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        int32(claims.ID),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to find account of refresh token")
		return exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if accountVersion != claims.Version {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.Version,
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

	var expiresAt pgtype.Timestamp
	if err := expiresAt.Scan(exp); err != nil {
		logger.ErrorContext(ctx, "Failed to scan the refresh token expires at", "error", err)
		return exceptions.NewServerError()
	}
	if err := s.database.BlacklistToken(ctx, database.BlacklistTokenParams{
		ID:        tokenID,
		ExpiresAt: expiresAt,
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

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        int32(claims.ID),
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
	if accountVersion != claims.Version {
		logger.WarnContext(ctx, "Account versions do not match",
			"claimsVersion", claims.Version,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	var expiresAt pgtype.Timestamp
	if err := expiresAt.Scan(exp); err != nil {
		logger.ErrorContext(ctx, "Failed to scan the refresh token expiresAt", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if err := s.database.BlacklistToken(ctx, database.BlacklistTokenParams{
		ID:        id,
		ExpiresAt: expiresAt,
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

var oauthScopes = []oauth.Scope{oauth.ScopeProfile}

const oAuthURLTTLSecs int64 = 120

type AccountOAuthURLOptions struct {
	RequestID   string
	Provider    string
	RedirectURL string
}

func (s *Services) AccountOAuthURL(ctx context.Context, opts AccountOAuthURLOptions) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "AccountOAuthURL").With(
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Getting OAuth authorization url...")

	authUrlOpts := oauth.AuthorizationURLOptions{
		RequestID:   opts.RequestID,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var oauthUrl, state string
	var serviceErr *exceptions.ServiceError
	switch opts.Provider {
	case AuthProviderApple:
		oauthUrl, state, serviceErr = s.oauthProviders.GetAppleAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderFacebook:
		oauthUrl, state, serviceErr = s.oauthProviders.GetFacebookAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderGitHub:
		oauthUrl, state, serviceErr = s.oauthProviders.GetGithubAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderGoogle:
		oauthUrl, state, serviceErr = s.oauthProviders.GetGoogleAuthorizationURL(ctx, authUrlOpts)
	case AuthProviderMicrosoft:
		oauthUrl, state, serviceErr = s.oauthProviders.GetMicrosoftAuthorizationURL(ctx, authUrlOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'apple', 'facebook', 'github', 'google' and 'microsoft'")
		return "", exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get authorization url or state", "error", serviceErr)
		return "", serviceErr
	}

	if err := s.cache.AddOAuthState(ctx, cache.AddOAuthStateOptions{
		RequestID:       opts.RequestID,
		State:           state,
		Provider:        opts.Provider,
		DurationSeconds: oAuthURLTTLSecs,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to cache state", "error", err)
		return "", exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Got authorization url successfully")
	return oauthUrl, nil
}

type extOAuthTokenOptions struct {
	requestID   string
	provider    string
	code        string
	state       string
	redirectURL string
}

func (s *Services) extOAuthToken(
	ctx context.Context,
	logger *slog.Logger,
	opts extOAuthTokenOptions,
) (string, *exceptions.ServiceError) {
	ok, err := s.cache.VerifyOAuthState(ctx, cache.VerifyOAuthStateOptions{
		RequestID: opts.requestID,
		State:     opts.state,
		Provider:  opts.provider,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth state", "error", err)
		return "", exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth state is invalid")
		return "", exceptions.NewValidationError("OAuth state is invalid")
	}

	accessTokenOpts := oauth.AccessTokenOptions{
		RequestID:   opts.requestID,
		Code:        opts.code,
		Scopes:      oauthScopes,
		RedirectURL: opts.redirectURL,
	}
	var token string
	var serviceErr *exceptions.ServiceError
	switch opts.provider {
	case AuthProviderFacebook:
		token, serviceErr = s.oauthProviders.GetFacebookAccessToken(ctx, accessTokenOpts)
	case AuthProviderGitHub:
		token, serviceErr = s.oauthProviders.GetGithubAccessToken(ctx, accessTokenOpts)
	case AuthProviderGoogle:
		token, serviceErr = s.oauthProviders.GetGoogleAccessToken(ctx, accessTokenOpts)
	case AuthProviderMicrosoft:
		token, serviceErr = s.oauthProviders.GetMicrosoftAccessToken(ctx, accessTokenOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'facebook', 'github', 'google' and 'microsoft'")
		return "", exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get oauth access token", "error", serviceErr)
		return "", serviceErr
	}

	logger.InfoContext(ctx, "Got access token successfully")
	return token, nil
}

type extOAuthUserOptions struct {
	requestID string
	provider  string
	token     string
}

func (s *Services) extOAuthUser(
	ctx context.Context,
	logger *slog.Logger,
	opts extOAuthUserOptions,
) (oauth.UserData, *exceptions.ServiceError) {
	userDataOpts := oauth.UserDataOptions{
		RequestID: opts.requestID,
		Token:     opts.token,
	}
	var userData oauth.UserData
	var serviceErr *exceptions.ServiceError
	switch opts.provider {
	case AuthProviderFacebook:
		userData, serviceErr = s.oauthProviders.GetFacebookUserData(ctx, userDataOpts)
	case AuthProviderGitHub:
		userData, serviceErr = s.oauthProviders.GetGithubUserData(ctx, userDataOpts)
	case AuthProviderGoogle:
		userData, serviceErr = s.oauthProviders.GetGoogleUserData(ctx, userDataOpts)
	case AuthProviderMicrosoft:
		userData, serviceErr = s.oauthProviders.GetMicrosoftUserData(ctx, userDataOpts)
	default:
		logger.ErrorContext(ctx, "Provider must be 'github' or 'google'")
		return oauth.UserData{}, exceptions.NewServerError()
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to fetch userData data", "error", serviceErr)
		return oauth.UserData{}, serviceErr
	}

	if !userData.IsVerified {
		logger.WarnContext(ctx, "External OAuth provider account is not verified")
		return oauth.UserData{}, exceptions.NewUnauthorizedError()
	}

	return userData, nil
}

type saveExtAccount struct {
	requestID string
	provider  string
	userData  *oauth.UserData
}

func (s *Services) saveExtAccount(
	ctx context.Context,
	logger *slog.Logger,
	opts saveExtAccount,
) (dtos.AccountDTO, *exceptions.ServiceError) {
	accountDto, serviceErr := s.GetAccountByEmail(ctx, GetAccountByEmailOptions{
		RequestID: opts.requestID,
		Email:     opts.userData.Email,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to get account by email", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		accountDto, serviceErr := s.CreateAccount(ctx, CreateAccountOptions{
			RequestID: opts.requestID,
			FirstName: opts.userData.FirstName,
			LastName:  opts.userData.LastName,
			Email:     opts.userData.Email,
			Provider:  opts.provider,
			Password:  "",
		})
		if serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to create account", "error", serviceErr)
			return dtos.AccountDTO{}, exceptions.NewServerError()
		}

		return accountDto, nil
	}

	prvdrOpts := database.FindAuthProviderByEmailAndProviderParams{
		Email:    accountDto.Email,
		Provider: opts.provider,
	}
	if _, err := s.database.FindAuthProviderByEmailAndProvider(ctx, prvdrOpts); err != nil {
		serviceErr = exceptions.FromDBError(err)
		if serviceErr.Code != exceptions.CodeNotFound {
			logger.ErrorContext(ctx, "Failed to find auth provider", "error", err)
			return dtos.AccountDTO{}, serviceErr
		}

		if err := s.database.CreateAuthProvider(ctx, database.CreateAuthProviderParams(prvdrOpts)); err != nil {
			logger.ErrorContext(ctx, "Failed to create auth provider", "error", err)
			return dtos.AccountDTO{}, exceptions.FromDBError(err)
		}
	}

	return accountDto, nil
}

type generateOAuthQueryParams struct {
	requestID string
	email     string
	token     string
}

func (s *Services) generateOAuthQueryParams(
	ctx context.Context,
	logger *slog.Logger,
	opts generateOAuthQueryParams,
) (string, *exceptions.ServiceError) {
	oauthTtl := s.jwt.GetOAuthTTL()
	code, err := s.cache.GenerateOAuthCode(ctx, cache.GenerateOAuthOptions{
		RequestID:       opts.requestID,
		Email:           opts.email,
		DurationSeconds: oauthTtl,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate oauth code", "error", err)
		return "", exceptions.NewServerError()
	}

	queryParams := make(url.Values)
	queryParams.Add("code", code)

	fragmentParams := make(url.Values)
	fragmentParams.Add("token_type", "Bearer")
	fragmentParams.Add("access_token", opts.token)
	fragmentParams.Add("expires_in", strconv.FormatInt(oauthTtl, 10))

	return fmt.Sprintf("%s#%s", queryParams.Encode(), fragmentParams.Encode()), nil
}

type ExtLoginAccountOptions struct {
	RequestID   string
	Provider    string
	Code        string
	State       string
	RedirectURL string
}

func (s *Services) ExtLoginAccount(
	ctx context.Context,
	opts ExtLoginAccountOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ExtLoginAccount").With(
		"provider", opts.Provider,
	)
	logger.InfoContext(ctx, "External logging in account...")

	token, serviceErr := s.extOAuthToken(ctx, logger, extOAuthTokenOptions{
		requestID:   opts.RequestID,
		provider:    opts.Provider,
		code:        opts.Code,
		state:       opts.State,
		redirectURL: opts.RedirectURL,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	userData, serviceErr := s.extOAuthUser(ctx, logger, extOAuthUserOptions{
		requestID: opts.RequestID,
		provider:  opts.Provider,
		token:     token,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	accountDTO, serviceErr := s.saveExtAccount(ctx, logger, saveExtAccount{
		requestID: opts.RequestID,
		provider:  opts.Provider,
		userData:  &userData,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	oauthToken, err := s.jwt.CreateOAuthToken(tokens.AccountTokenOptions{
		ID:      accountDTO.ID,
		Version: accountDTO.Version(),
		Email:   accountDTO.Email,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth Token", "error", err)
		return "", exceptions.NewServerError()
	}

	return s.generateOAuthQueryParams(ctx, logger, generateOAuthQueryParams{
		requestID: opts.RequestID,
		email:     accountDTO.Email,
		token:     oauthToken,
	})
}

type AppleLoginAccountOptions struct {
	RequestID string
	FirstName string
	LastName  string
	Email     string
	Code      string
	State     string
}

func (s *Services) AppleLoginAccount(
	ctx context.Context,
	opts AppleLoginAccountOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "AppleLoginAccount").With(
		"firstName", opts.FirstName,
		"lastName", opts.LastName,
	)
	logger.InfoContext(ctx, "Apple account logging in...")

	ok, err := s.cache.VerifyOAuthState(ctx, cache.VerifyOAuthStateOptions{
		RequestID: opts.RequestID,
		State:     opts.State,
		Provider:  AuthProviderApple,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify oauth state", "error", err)
		return "", exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth state is invalid")
		return "", exceptions.NewValidationError("OAuth state is invalid")
	}

	idToken, serviceErr := s.oauthProviders.GetAppleIDToken(ctx, oauth.AccessTokenOptions{
		RequestID: opts.RequestID,
		Code:      opts.Code,
		Scopes:    oauthScopes,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get apple AccountID token", "error", serviceErr)
		return "", serviceErr
	}

	ok, serviceErr = s.oauthProviders.ValidateAppleIDToken(ctx, oauth.ValidateAppleIDTokenOptions{
		RequestID: opts.RequestID,
		Token:     idToken,
		Email:     opts.Email,
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to validate apple AccountID token", "error", serviceErr)
		return "", serviceErr
	}
	if !ok {
		logger.WarnContext(ctx, "Apple account is not verified")
		return "", exceptions.NewUnauthorizedError()
	}

	userData := oauth.NewAppleUserData(opts.Email, opts.FirstName, opts.LastName)
	accountDTO, serviceErr := s.saveExtAccount(ctx, logger, saveExtAccount{
		requestID: opts.RequestID,
		provider:  AuthProviderApple,
		userData:  &userData,
	})
	if serviceErr != nil {
		return "", serviceErr
	}

	oauthToken, err := s.jwt.CreateOAuthToken(tokens.AccountTokenOptions{
		ID:      accountDTO.ID,
		Version: accountDTO.Version(),
		Email:   accountDTO.Email,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate OAuth Token", "error", err)
		return "", exceptions.NewServerError()
	}

	return s.generateOAuthQueryParams(ctx, logger, generateOAuthQueryParams{
		requestID: opts.RequestID,
		email:     accountDTO.Email,
		token:     oauthToken,
	})
}

type OAuthLoginAccountOptions struct {
	RequestID string
	ID        int32
	Version   int
	Code      string
}

func (s *Services) OAuthLoginAccount(
	ctx context.Context,
	opts OAuthLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "OAuthLoginAccount").With("accountId", opts.ID)
	logger.InfoContext(ctx, "OAuth account logging in...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
	})
	if serviceErr != nil {
		if serviceErr.Code != exceptions.CodeNotFound {
			return dtos.AuthDTO{}, serviceErr
		}

		logger.WarnContext(ctx, "Account was not found", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountVersion := accountDTO.Version()
	if accountVersion != opts.Version {
		logger.WarnContext(ctx, "Account versions do not match",
			"accessTokenVersion", opts.Version,
			"accountVersion", accountVersion,
		)
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	ok, err := s.cache.VerifyOAuthCode(ctx, cache.VerifyOAuthCodeOptions{
		RequestID: opts.RequestID,
		Email:     accountDTO.Email,
		Code:      opts.Code,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to verify OAuth code", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth code verification failed")
		return dtos.AuthDTO{}, exceptions.NewValidationError("OAuth code verification failed")
	}

	return s.GenerateFullAuthDTO(
		ctx,
		logger,
		&accountDTO,
		[]tokens.AccountScope{tokens.AccountScopeAdmin},
		"OAuth logged in successfully",
	)
}

func processAccountClientCredentialsScopes(ccScopes []string, scopes []string) ([]string, *exceptions.ServiceError) {
	if len(scopes) == 0 {
		return ccScopes, nil
	}

	for _, scope := range scopes {
		if !slices.Contains(ccScopes, scope) {
			return nil, exceptions.NewUnauthorizedError()
		}
	}
	if !slices.Contains(scopes, tokens.AccountScopeClientCredentials) {
		scopes = append(scopes, tokens.AccountScopeClientCredentials)
	}

	return scopes, nil
}

type ClientCredentialsLoginAccountOptions struct {
	RequestID    string
	Audience     string
	Scopes       []string
	ClientID     string
	ClientSecret string
}

func (s *Services) ClientCredentialsLoginAccount(
	ctx context.Context,
	opts ClientCredentialsLoginAccountOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, authLocation, "ClientCredentialsLoginAccount").With(
		"clientId", opts.ClientID,
	)
	logger.InfoContext(ctx, "Client credentials logging in account...")

	accountClientCredentialsDTO, serviceErr := s.GetAccountCredentialsByClientID(ctx,
		GetAccountCredentialsByClientIDOptions{
			RequestID: opts.RequestID,
			ClientID:  opts.ClientID,
		},
	)
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Account keys not found", "error", serviceErr)
			return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
		}

		return dtos.AuthDTO{}, serviceErr
	}

	ok, err := utils.CompareHash(opts.ClientSecret, accountClientCredentialsDTO.HashedSecret())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to compare client secret hashes", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "Client secret verification failed")
		return dtos.AuthDTO{}, exceptions.NewUnauthorizedError()
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        int32(accountClientCredentialsDTO.AccountID()),
	})
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get account", "error", serviceErr)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	scopes, serviceErr := processAccountClientCredentialsScopes(accountClientCredentialsDTO.Scopes, opts.Scopes)
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to process client credentials scopes", "error", serviceErr)
		return dtos.AuthDTO{}, serviceErr
	}

	accessToken, err := s.jwt.CreateAccessToken(tokens.AccountTokenOptions{
		ID:       accountDTO.ID,
		Version:  accountDTO.Version(),
		Email:    accountDTO.Email,
		Audience: opts.Audience,
		Scopes:   scopes,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "Client credential logged in successfully")
	return dtos.NewAuthDTO(accessToken, s.jwt.GetAccountCredentialsTTL()), nil
}

func (s *Services) GetAccountPublicJWKs(ctx context.Context, requestID string) dtos.JWKsDTO {
	logger := s.buildLogger(requestID, authLocation, "GetAccountPublicKeys")
	logger.InfoContext(ctx, "Getting account public JWKs...")

	jwks := s.jwt.JWKs()

	logger.InfoContext(ctx, "Got account public JWKs successfully")
	return dtos.NewJWKsDTO(jwks)
}

type updateAccount2FAOptions struct {
	requestID   string
	id          int
	email       string
	prev2FAType string
}

func (s *Services) disableAccount2FA(
	ctx context.Context,
	opts updateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, accountsLocation, "disableAccount2FA").With(
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
	logger := s.buildLogger(opts.requestID, accountsLocation, "updateAccountTOTP2FA").With(
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
		Dek:           totpKey.EncryptedDEK(),
		RecoveryCodes: totpKey.HashedCodes(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to create account recovery keys", "error", err)
		serviceErr = exceptions.FromDBError(err)
		return dtos.AuthDTO{}, serviceErr
	}

	token, err := s.jwt.Create2FAToken(tokens.AccountTokenOptions{
		ID:      int(account.ID),
		Version: int(account.Version),
		Email:   account.Email,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate 2FA access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewAuthDTOWithData(
		token,
		"Please scan QR code with your authentication app",
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
	logger := s.buildLogger(opts.requestID, accountsLocation, "updateAccountEmail2FA").With(
		"id", opts.id,
	)
	logger.InfoContext(ctx, "Update account email 2FA...")

	code, err := s.cache.AddTwoFactorCode(ctx, cache.AddTwoFactorCodeOptions{
		RequestID: opts.requestID,
		AccountID: opts.id,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate two factor code", "error", err)
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
		Name:      fmt.Sprintf("%s %s", account.FirstName, account.LastName),
		Code:      code,
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to publish two factor email", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	token, err := s.jwt.Create2FAToken(tokens.AccountTokenOptions{
		ID:      int(account.ID),
		Version: int(account.Version),
		Email:   account.Email,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate 2FA access token", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	return dtos.NewTempAuthDTO(token, "Please provide email two factor code", s.jwt.Get2FATTL()), nil
}

type UpdateAccount2FAOptions struct {
	RequestID     string
	ID            int32
	TwoFactorType string
	Password      string
}

func (s *Services) UpdateAccount2FA(
	ctx context.Context,
	opts UpdateAccount2FAOptions,
) (dtos.AuthDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, accountsLocation, "UpdateAccount2FA").With(
		"id", opts.ID,
		"twoFactorType", opts.TwoFactorType,
	)
	logger.InfoContext(ctx, "Updating account 2FA...")

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.RequestID,
		ID:        opts.ID,
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
			logger.WarnContext(ctx, "Email auth provider not found", "error", err)
			return dtos.AuthDTO{}, exceptions.NewForbiddenError()
		}

		logger.ErrorContext(ctx, "Failed to get auth provider", "error", err)
		return dtos.AuthDTO{}, exceptions.NewServerError()
	}

	if accountDTO.TwoFactorType == opts.TwoFactorType {
		logger.InfoContext(ctx, "Account already uses given 2FA type")

		token, err := s.jwt.CreateAccessToken(tokens.AccountTokenOptions{
			ID:      accountDTO.ID,
			Version: accountDTO.Version(),
			Email:   accountDTO.Email,
			Scopes:  []tokens.AccountScope{tokens.AccountScopeAdmin},
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
		id:          accountDTO.ID,
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
