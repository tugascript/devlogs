package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const userOAuthLocation string = "user_oauth"

type userCustomOAuthURLOptions struct {
	requestID   string
	accountID   int32
	provider    string
	redirectURL string
}

func (s *Services) userCustomOAuthURL(
	ctx context.Context,
	opts userCustomOAuthURLOptions,
) (string, string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, userOAuthLocation, "userCustomOAuthURL").With(
		"accountId", opts.accountID,
		"Provider", opts.provider,
	)
	logger.InfoContext(ctx, "Generating custom OAuth URL...")

	// TODO: add cached to getExternalAuthProviderByProvider
	authProvider, serviceErr := s.GetExternalAuthProviderByProvider(ctx, GetExternalAuthProviderByProviderOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		Provider:  opts.provider,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get external auth Provider", "error", serviceErr)
		return "", "", serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.requestID,
		ID:        opts.accountID,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by ID", "error", serviceErr)
		return "", "", serviceErr
	}

	secret, dek, err := s.encrypt.DecryptWithAccountDEK(ctx, encryption.DecryptWithAccountDEKOptions{
		RequestID:     opts.requestID,
		StoredDEK:     accountDTO.DEK(),
		EncryptedText: authProvider.EncryptClientSecret(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt client secret", "error", err)
		return "", "", exceptions.NewServerError()
	}

	if dek != "" {
		if serviceErr := s.UpdateAccountDEK(ctx, UpdateAccountDEKOptions{
			RequestID: opts.requestID,
			ID:        opts.accountID,
			DEK:       dek,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to update account DEK", "error", serviceErr)
			return "", "", serviceErr
		}
	}

	return s.oauthProviders.GetCustomAuthorizationURL(
		ctx,
		oauth.GetCustomAuthorizationURLOptions{
			RequestID:    opts.requestID,
			RedirectURL:  opts.redirectURL,
			ClientID:     authProvider.ClientID,
			ClientSecret: secret,
			AuthURL:      authProvider.AuthURL,
			TokenURL:     authProvider.TokenURL,
			Scopes:       authProvider.Scopes,
		},
	)
}

type UserOAuthURLOptions struct {
	RequestID   string
	AccountID   int32
	AppClientID string
	Provider    string
	RedirectURL string
}

func (s *Services) UserOAuthURL(
	ctx context.Context,
	opts UserOAuthURLOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userOAuthLocation, "UserOAuthURL").With(
		"accountId", opts.AccountID,
		"appClientId", opts.AppClientID,
		"Provider", opts.Provider,
	)
	logger.InfoContext(ctx, "Generating OAuth URL...")

	appDTO, serviceErr := s.GetAppByClientID(ctx, GetAppByClientIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		ClientID:  opts.AppClientID,
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found", "error", serviceErr)
			return "", exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by client ID", "error", serviceErr)
		return "", serviceErr
	}

	authUrlOpts := oauth.AuthorizationURLOptions{
		RequestID:   opts.RequestID,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var oauthUrl, state string
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
		oauthUrl, state, serviceErr = s.userCustomOAuthURL(ctx, userCustomOAuthURLOptions{
			requestID:   opts.RequestID,
			accountID:   opts.AccountID,
			provider:    opts.Provider,
			redirectURL: opts.RedirectURL,
		})
	}
	if serviceErr != nil {
		logger.ErrorContext(ctx, "Failed to get authorization url or State", "error", serviceErr)
		return "", serviceErr
	}
	if err := s.cache.AddUserOAuthState(ctx, cache.AddUserOAuthStateOptions{
		RequestID:       opts.RequestID,
		State:           state,
		AccountID:       opts.AccountID,
		AppID:           int32(appDTO.ID()),
		Provider:        opts.Provider,
		DurationSeconds: s.jwt.GetOAuthTTL(),
	}); err != nil {
		logger.ErrorContext(ctx, "Failed to add user OAuth State", "error", err)
		return "", exceptions.NewServerError()
	}

	logger.InfoContext(ctx, "OAuth URL generated successfully")
	return oauthUrl, nil
}

type userCustomOAuthTokenOptions struct {
	requestID   string
	accountID   int32
	provider    string
	code        string
	redirectURL string
}

func (s *Services) userCustomOAuthToken(
	ctx context.Context,
	opts userCustomOAuthTokenOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, userOAuthLocation, "userCustomOAuthToken").With(
		"accountId", opts.accountID,
		"Provider", opts.provider,
	)
	logger.InfoContext(ctx, "Getting custom OAuth token...")

	// TODO: add cached to getExternalAuthProviderByProvider
	authProvider, serviceErr := s.GetExternalAuthProviderByProvider(ctx, GetExternalAuthProviderByProviderOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		Provider:  opts.provider,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get external auth Provider", "error", serviceErr)
		return "", serviceErr
	}

	accountDTO, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{
		RequestID: opts.requestID,
		ID:        opts.accountID,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get account by ID", "error", serviceErr)
		return "", serviceErr
	}

	secret, dek, err := s.encrypt.DecryptWithAccountDEK(ctx, encryption.DecryptWithAccountDEKOptions{
		RequestID:     opts.requestID,
		StoredDEK:     accountDTO.DEK(),
		EncryptedText: authProvider.EncryptClientSecret(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to decrypt client secret", "error", err)
		return "", exceptions.NewServerError()
	}

	if dek != "" {
		if serviceErr := s.UpdateAccountDEK(ctx, UpdateAccountDEKOptions{
			RequestID: opts.requestID,
			ID:        opts.accountID,
			DEK:       dek,
		}); serviceErr != nil {
			logger.ErrorContext(ctx, "Failed to update account DEK", "error", serviceErr)
			return "", serviceErr
		}
	}

	return s.oauthProviders.GetCustomAccessToken(ctx, oauth.GetCustomAccessTokenOptions{
		RequestID:    opts.requestID,
		RedirectURL:  opts.redirectURL,
		ClientID:     authProvider.ClientID,
		ClientSecret: secret,
		AuthURL:      authProvider.AuthURL,
		TokenURL:     authProvider.TokenURL,
		Scopes:       authProvider.Scopes,
		Code:         opts.code,
	})
}

type ExtUserOAuthTokenOptions struct {
	RequestID   string
	AccountID   int32
	Provider    string
	Code        string
	State       string
	RedirectURL string
}

func (s *Services) ExtUserOAuthToken(
	ctx context.Context,
	opts ExtUserOAuthTokenOptions,
) (string, dtos.AppDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, userOAuthLocation, "ExtUserOAuthToken").With(
		"accountId", opts.AccountID,
		"Provider", opts.Provider,
	)

	appID, ok, err := s.cache.GetOAuthStateAppID(ctx, cache.GetOAuthStateAppIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		State:     opts.State,
		Provider:  opts.Provider,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to get OAuth State app ID", "error", err)
		return "", dtos.AppDTO{}, exceptions.NewServerError()
	}
	if !ok {
		logger.WarnContext(ctx, "OAuth State not found")
		return "", dtos.AppDTO{}, exceptions.NewUnauthorizedError()
	}

	appDTO, serviceErr := s.GetAppByID(ctx, GetAppByIDOptions{
		RequestID: opts.RequestID,
		AccountID: opts.AccountID,
		AppID:     int32(appID),
	})
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "App not found", "error", serviceErr)
			return "", dtos.AppDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get app by ID", "error", serviceErr)
		return "", dtos.AppDTO{}, serviceErr
	}

	accessTokenOpts := oauth.AccessTokenOptions{
		RequestID:   opts.RequestID,
		Code:        opts.Code,
		Scopes:      oauthScopes,
		RedirectURL: opts.RedirectURL,
	}
	var token string
	switch opts.Provider {
	case AuthProviderFacebook:
		token, serviceErr = s.oauthProviders.GetFacebookAccessToken(ctx, accessTokenOpts)
	case AuthProviderGitHub:
		token, serviceErr = s.oauthProviders.GetGithubAccessToken(ctx, accessTokenOpts)
	case AuthProviderGoogle:
		token, serviceErr = s.oauthProviders.GetGoogleAccessToken(ctx, accessTokenOpts)
	case AuthProviderMicrosoft:
		token, serviceErr = s.oauthProviders.GetMicrosoftAccessToken(ctx, accessTokenOpts)
	default:
		token, serviceErr = s.userCustomOAuthToken(ctx, userCustomOAuthTokenOptions{
			requestID:   opts.RequestID,
			accountID:   opts.AccountID,
			provider:    opts.Provider,
			code:        opts.Code,
			redirectURL: opts.RedirectURL,
		})
	}
	if serviceErr != nil {
		if serviceErr.Code == exceptions.CodeNotFound {
			logger.WarnContext(ctx, "Failed to get access token", "error", serviceErr)
			return "", dtos.AppDTO{}, exceptions.NewUnauthorizedError()
		}

		logger.ErrorContext(ctx, "Failed to get access token", "error", serviceErr)
		return "", dtos.AppDTO{}, serviceErr
	}

	return token, appDTO, nil
}

type getCustomUserOptions struct {
	requestID string
	accountID int32
	provider  string
	token     string
}

func (s *Services) getCustomUser(
	ctx context.Context,
	opts getCustomUserOptions,
) (string, map[string]any, map[string]string, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.requestID, userOAuthLocation, "getCustomUser").With(
		"accountId", opts.accountID,
		"provider", opts.provider,
	)
	logger.InfoContext(ctx, "Getting custom user...")

	authProviderDTO, serviceErr := s.GetExternalAuthProviderByProvider(ctx, GetExternalAuthProviderByProviderOptions{
		RequestID: opts.requestID,
		AccountID: opts.accountID,
		Provider:  opts.provider,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get external auth Provider", "error", serviceErr)
		return "", nil, nil, serviceErr
	}

	email, userMap, serviceErr := s.oauthProviders.GetCustomUserData(ctx, oauth.GetCustomUserDataOptions{
		RequestID:   opts.requestID,
		Token:       opts.token,
		UserDataURL: authProviderDTO.UserInfoURL,
		EmailKey:    authProviderDTO.EmailKey,
	})
	if serviceErr != nil {
		logger.WarnContext(ctx, "Failed to get custom user data", "error", serviceErr)
		return "", nil, nil, serviceErr
	}

	return email, userMap, authProviderDTO.UserMapping, nil
}

// type GetAndSaveExtUserOptions struct {
// 	RequestID        string
// 	AccountID        int32
// 	AppID            int32
// 	AppProfileSchema dtos.SchemaDTO
// 	Provider         string
// 	Token            string
// }

// func (s *Services) GetAndSaveExtUser(
// 	ctx context.Context,
// 	opts GetAndSaveExtUserOptions,
// ) (dtos.AuthDTO, *exceptions.ServiceError) {
// 	logger := s.buildLogger(opts.RequestID, userOAuthLocation, "GetExtUser").With(
// 		"accountId", opts.AccountID,
// 		"appId", opts.AppID,
// 		"Provider", opts.Provider,
// 	)
// 	logger.InfoContext(ctx, "Getting external user...")

// 	userSchemaDTO, serviceErr := s.GetOrCreateUserSchema(ctx, GetOrCreateUserSchemaOptions{
// 		RequestID: opts.RequestID,
// 		AccountID: opts.AccountID,
// 	})
// 	if serviceErr != nil {
// 		logger.ErrorContext(ctx, "Failed to get or create user schema", "error", serviceErr)
// 		return dtos.AuthDTO{}, serviceErr
// 	}

// 	userDataOpts := oauth.UserDataOptions{
// 		RequestID: opts.RequestID,
// 		Token:     opts.Token,
// 	}
// 	var userEmail string
// 	var userMap map[string]any
// 	switch opts.Provider {
// 	case AuthProviderApple:
// 		logger.WarnContext(ctx, "Apple OAuth provider has a custom user get flow")
// 		return dtos.AuthDTO{}, exceptions.NewNotFoundError()
// 	case AuthProviderFacebook:
// 		userEmail, userMap, serviceErr = s.oauthProviders.GetFacebookUserMap(ctx, userDataOpts)
// 	case AuthProviderGitHub:
// 		userEmail, userMap, serviceErr = s.oauthProviders.GetGithubUserMap(ctx, userDataOpts)
// 	case AuthProviderGoogle:
// 		userEmail, userMap, serviceErr = s.oauthProviders.GetGoogleUserMap(ctx, userDataOpts)
// 	case AuthProviderMicrosoft:
// 		userEmail, userMap, serviceErr = s.oauthProviders.GetMicrosoftUserMap(ctx, userDataOpts)
// 	}
// 	if serviceErr != nil {
// 		logger.ErrorContext(ctx, "Failed to fetch userData data", "error", serviceErr)
// 		return dtos.AuthDTO{}, serviceErr
// 	}
// }
