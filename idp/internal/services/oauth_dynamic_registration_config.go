package services

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const oauthDynamicRegistrationConfigLocation = "oauth_dynamic_registration_config"

type GetRegisteredClientOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
	BackendDomain   string
	HostUsername    string
}

func (s *Services) getActiveAccountCredentialSecretAndKey(
	ctx context.Context,
	requestID string,
	accountCredID int32,
	authMethod database.AuthMethod,
) (string, time.Time, utils.JWK, *exceptions.ServiceError) {
	switch authMethod {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		secretEnt, err := s.database.FindCurrentAccountCredentialSecretByAccountCredentialID(ctx, accountCredID)
		if err != nil {
			return "", time.Time{}, nil, nil
		}
		decryptedSecret, decryptErr := s.crypto.DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
			RequestID: requestID,
			GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, BuildGetGlobalDEKFnOptions{
				RequestID: requestID,
			}),
			GetEncryptDEKfn: s.BuildGetEncGlobalDEKFn(ctx, BuildGetGlobalDEKFnOptions{
				RequestID: requestID,
			}),
			StoreReEncryptedDataFn: func(
				_ crypto.EntityID,
				dekID crypto.DEKID,
				ciphertext crypto.DEKCiphertext,
			) *exceptions.ServiceError {
				if err := s.database.UpdateCredentialsSecretClientSecret(
					ctx,
					database.UpdateCredentialsSecretClientSecretParams{
						ID:           secretEnt.ID,
						ClientSecret: ciphertext,
						DekKid:       dekID,
					},
				); err != nil {
					return exceptions.FromDBError(err)
				}
				return nil
			},
			EntityID:   secretEnt.SecretID,
			Ciphertext: secretEnt.ClientSecret,
		})
		if decryptErr != nil {
			return "", time.Time{}, nil, decryptErr
		}
		return fmt.Sprintf("%s.%s", secretEnt.SecretID, decryptedSecret), secretEnt.ExpiresAt, nil, nil
	case database.AuthMethodPrivateKeyJwt:
		keyEnt, err := s.database.FindCurrentAccountCredentialKeyByAccountCredentialID(ctx, accountCredID)
		if err != nil {
			return "", time.Time{}, nil, nil
		}
		jwk, _ := utils.JsonToJWK(keyEnt.PublicKey)
		return "", keyEnt.ExpiresAt, jwk, nil
	default:
		return "", time.Time{}, nil, nil
	}
}

func (s *Services) getActiveAppSecretAndKey(
	ctx context.Context,
	requestID string,
	accountID int32,
	appID int32,
	authMethod database.AuthMethod,
) (string, time.Time, utils.JWK, *exceptions.ServiceError) {
	switch authMethod {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		secrets, err := s.database.FindPaginatedAppSecretsByAppID(ctx, database.FindPaginatedAppSecretsByAppIDParams{
			AppID:  appID,
			Offset: 0,
			Limit:  10,
		})
		if err != nil || len(secrets) == 0 {
			return "", time.Time{}, nil, nil
		}
		var activeSecret *database.CredentialsSecret
		now := time.Now()
		for i := range secrets {
			if !secrets[i].IsRevoked && secrets[i].ExpiresAt.After(now) {
				activeSecret = &secrets[i]
				break
			}
		}
		if activeSecret == nil {
			return "", time.Time{}, nil, nil
		}
		decryptedSecret, decryptErr := s.crypto.DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
			RequestID: requestID,
			GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
				RequestID: requestID,
				AccountID: accountID,
			}),
			GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: requestID,
				AccountID: accountID,
			}),
			StoreReEncryptedDataFn: func(
				_ crypto.EntityID,
				dekID crypto.DEKID,
				ciphertext crypto.DEKCiphertext,
			) *exceptions.ServiceError {
				if err := s.database.UpdateCredentialsSecretClientSecret(
					ctx,
					database.UpdateCredentialsSecretClientSecretParams{
						ID:           activeSecret.ID,
						ClientSecret: ciphertext,
						DekKid:       dekID,
					},
				); err != nil {
					return exceptions.FromDBError(err)
				}
				return nil
			},
			EntityID:   activeSecret.SecretID,
			Ciphertext: activeSecret.ClientSecret,
		})
		if decryptErr != nil {
			return "", time.Time{}, nil, decryptErr
		}
		return fmt.Sprintf("%s.%s", activeSecret.SecretID, decryptedSecret), activeSecret.ExpiresAt, nil, nil
	case database.AuthMethodPrivateKeyJwt:
		keys, err := s.database.FindPaginatedAppKeysByAppID(ctx, database.FindPaginatedAppKeysByAppIDParams{
			AppID:  appID,
			Offset: 0,
			Limit:  10,
		})
		if err != nil || len(keys) == 0 {
			return "", time.Time{}, nil, nil
		}
		now := time.Now()
		for i := range keys {
			if !keys[i].IsRevoked && keys[i].ExpiresAt.After(now) {
				jwk, _ := utils.JsonToJWK(keys[i].PublicKey)
				return "", keys[i].ExpiresAt, jwk, nil
			}
		}
		return "", time.Time{}, nil, nil
	default:
		return "", time.Time{}, nil, nil
	}
}

func (s *Services) GetRegisteredAccountCredentials(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	row, serviceErr := s.findRegisteredAccountCredential(ctx, opts)
	if serviceErr != nil {
		return nil, serviceErr
	}
	secret, exp, key, serviceErr := s.getActiveAccountCredentialSecretAndKey(
		ctx,
		opts.RequestID,
		row.ID,
		row.TokenEndpointAuthMethod,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	account, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	token, serviceErr := s.CreateAccountCredentialsRegistrationAccessToken(ctx, CreateAccountCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  account.Version(),
		ClientID:        row.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(row, "", secret, exp, key)
	if serviceErr != nil {
		return nil, exceptions.NewUnauthorizedError()
	}
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(opts.BackendDomain, row.ClientID))
	return dto.Registration, nil
}

func (s *Services) GetRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	row, serviceErr := s.findRegisteredApp(ctx, opts)
	if serviceErr != nil {
		return nil, serviceErr
	}
	secret, exp, key, serviceErr := s.getActiveAppSecretAndKey(
		ctx, opts.RequestID, row.AccountID, row.ID, row.TokenEndpointAuthMethod,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	account, serviceErr := s.GetAccountByPublicID(ctx, GetAccountByPublicIDOptions{
		RequestID: opts.RequestID,
		PublicID:  opts.AccountPublicID,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	token, serviceErr := s.CreateAppCredentialsRegistrationAccessToken(ctx, CreateAppCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  account.Version(),
		ClientID:        row.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto := dtos.MapRegisteredApp(row, "", secret, exp, key)
	issuer := dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain)
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(issuer, row.ClientID))
	return dto.Registration, nil
}

func (s *Services) DeleteRegisteredAccountCredentials(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) *exceptions.ServiceError {
	if _, serviceErr := s.findRegisteredAccountCredential(ctx, opts); serviceErr != nil {
		return serviceErr
	}
	if err := s.database.DeleteAccountCredentials(ctx, opts.ClientID); err != nil {
		return exceptions.FromDBError(err)
	}
	return nil
}

func (s *Services) DeleteRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) *exceptions.ServiceError {
	row, serviceErr := s.findRegisteredApp(ctx, opts)
	if serviceErr != nil {
		return serviceErr
	}
	if err := s.database.DeleteApp(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	return nil
}

func (s *Services) findRegisteredAccountCredential(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*database.AccountCredential, *exceptions.ServiceError) {
	row, err := s.database.FindAccountCredentialsByAccountPublicIDAndClientID(ctx, database.FindAccountCredentialsByAccountPublicIDAndClientIDParams{
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.ClientID,
	})
	if err != nil {
		return nil, exceptions.NewError(exceptions.OAuthErrorInvalidToken, "client not found")
	}
	return &row, nil
}

func (s *Services) findRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*database.App, *exceptions.ServiceError) {
	row, err := s.database.FindAppByClientIDAndAccountPublicID(ctx, database.FindAppByClientIDAndAccountPublicIDParams{
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.ClientID,
	})
	if err != nil {
		return nil, exceptions.NewError(exceptions.OAuthErrorInvalidToken, "client not found")
	}
	return &row, nil
}

type UpdateRegisteredClientOptions struct {
	CreateAccountCredentialsRegistrationOptions
	ClientID              string
	SubmittedClientID     string
	SubmittedClientSecret string
}

func (s *Services) UpdateRegisteredAccountCredentials(
	ctx context.Context,
	opts UpdateRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationConfigLocation, "UpdateRegisteredAccountCredentials")
	if opts.SubmittedClientID == "" || opts.SubmittedClientID != opts.ClientID {
		return nil, exceptions.NewError(exceptions.OAuthErrorInvalidRequest, "client_id is required and must match the client making the request")
	}
	existing, serviceErr := s.findRegisteredAccountCredential(ctx, GetRegisteredClientOptions{
		RequestID: opts.RequestID, AccountPublicID: opts.AccountPublicID, ClientID: opts.ClientID,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	currentSecret, exp, key, serviceErr := s.getActiveAccountCredentialSecretAndKey(
		ctx,
		opts.RequestID,
		existing.ID,
		existing.TokenEndpointAuthMethod,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	if opts.SubmittedClientSecret != "" {
		if currentSecret == "" || subtle.ConstantTimeCompare([]byte(opts.SubmittedClientSecret), []byte(currentSecret)) != 1 {
			return nil, exceptions.NewError(exceptions.OAuthErrorInvalidClient, "invalid client secret")
		}
	}
	data := registrationDataFromAccountOptions(opts.CreateAccountCredentialsRegistrationOptions)
	data.ApplicationType = string(existing.CredentialsType)
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountPublicID: opts.AccountPublicID, data: data,
		softwareStatement: opts.SoftwareStatement, backendDomain: opts.BackendDomain,
		frontendDomain: opts.FrontendDomain, app: false,
	})
	if preparationErr != nil {
		return nil, preparationErr
	}
	if data.ApplicationType != string(existing.CredentialsType) {
		return nil, exceptions.NewValidationError("application_type cannot be changed")
	}
	parsedClientURI, err := url.Parse(data.ClientURI)
	if err != nil {
		return nil, exceptions.NewValidationError("invalid client URI")
	}
	scopes, serviceErr := mapAccountCredentialsScopes(strings.Fields(data.Scope))
	if serviceErr != nil {
		return nil, serviceErr
	}
	tokenEndpointAuthMethod, serviceErr := mapAuthMethod(data.TokenEndpointAuthMethod)
	if serviceErr != nil {
		return nil, serviceErr
	}
	params, serviceErr := s.mapAccountCredentialsRegistrationDataToDBParams(ctx, mapAccountCredentialsRegistrationDataToDBParamsOptions{
		applicationType:         existing.CredentialsType,
		accountPublicID:         opts.AccountPublicID,
		accountID:               existing.AccountID,
		domain:                  parsedClientURI.Hostname(),
		requestID:               opts.RequestID,
		tokenEndpointAuthMethod: tokenEndpointAuthMethod,
		transport:               existing.Transport,
		scopes:                  scopes,
		data:                    &data,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	updated, err := s.database.UpdateRegisteredAccountCredentials(ctx, database.UpdateRegisteredAccountCredentialsParams{
		ID: existing.ID, Domain: params.Domain, Transport: params.Transport, RedirectUris: params.RedirectUris,
		TokenEndpointAuthMethod: params.TokenEndpointAuthMethod, GrantTypes: params.GrantTypes, ResponseTypes: params.ResponseTypes,
		ClientName: params.ClientName, ClientUri: params.ClientUri, LogoUri: params.LogoUri, Scopes: params.Scopes,
		Contacts: params.Contacts, TosUri: params.TosUri, PolicyUri: params.PolicyUri, JwksUri: params.JwksUri, Jwks: params.Jwks,
		SoftwareID: params.SoftwareID, SoftwareVersion: params.SoftwareVersion, SectorIdentifierUri: params.SectorIdentifierUri,
		SubjectType: params.SubjectType, IDTokenSignedResponseAlg: params.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg: params.IDTokenEncryptedResponseAlg, IDTokenEncryptedResponseEnc: params.IDTokenEncryptedResponseEnc,
		UserinfoSignedResponseAlg: params.UserinfoSignedResponseAlg, UserinfoEncryptedResponseAlg: params.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: params.UserinfoEncryptedResponseEnc, RequestObjectSigningAlg: params.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg: params.RequestObjectEncryptionAlg, RequestObjectEncryptionEnc: params.RequestObjectEncryptionEnc,
		TokenEndpointAuthSigningAlg: params.TokenEndpointAuthSigningAlg, DefaultMaxAge: params.DefaultMaxAge,
		RequireAuthTime: params.RequireAuthTime, DefaultAcrValues: params.DefaultAcrValues, InitiateLoginUri: params.InitiateLoginUri,
		RequestUris: params.RequestUris, AccessTokenSigningAlg: params.AccessTokenSigningAlg,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update account credentials", "error", err)
		return nil, exceptions.FromDBError(err)
	}
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(&updated, opts.SoftwareStatement, currentSecret, exp, key)
	if serviceErr != nil {
		return nil, serviceErr
	}
	token, serviceErr := s.CreateAccountCredentialsRegistrationAccessToken(ctx, CreateAccountCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: opts.AccountPublicID,
		AccountVersion:  opts.AccountVersion,
		ClientID:        updated.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(opts.BackendDomain, updated.ClientID))
	return dto.Registration, nil
}

type UpdateRegisteredAppOptions struct {
	CreateAppCredentialsRegistrationOptions
	ClientID              string
	SubmittedClientID     string
	SubmittedClientSecret string
	HostUsername          string
}

func (s *Services) UpdateRegisteredApp(
	ctx context.Context,
	opts UpdateRegisteredAppOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationConfigLocation, "UpdateRegisteredApp")
	if opts.SubmittedClientID == "" || opts.SubmittedClientID != opts.ClientID {
		return nil, exceptions.NewError(exceptions.OAuthErrorInvalidRequest, "client_id is required and must match the client making the request")
	}
	account, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{RequestID: opts.RequestID, ID: opts.AccountID})
	if serviceErr != nil {
		return nil, exceptions.NewError(exceptions.OAuthErrorInvalidToken, "account not found")
	}
	existing, serviceErr := s.findRegisteredApp(ctx, GetRegisteredClientOptions{
		RequestID: opts.RequestID, AccountPublicID: account.PublicID, ClientID: opts.ClientID,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	currentSecret, exp, key, serviceErr := s.getActiveAppSecretAndKey(
		ctx, opts.RequestID, existing.AccountID, existing.ID, existing.TokenEndpointAuthMethod,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	if opts.SubmittedClientSecret != "" {
		if currentSecret == "" || subtle.ConstantTimeCompare([]byte(opts.SubmittedClientSecret), []byte(currentSecret)) != 1 {
			return nil, exceptions.NewError(exceptions.OAuthErrorInvalidClient, "invalid client secret")
		}
	}
	data := registrationDataFromAppOptions(opts.CreateAppCredentialsRegistrationOptions)
	data.ApplicationType = string(existing.AppType)
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountID: opts.AccountID, data: data,
		softwareStatement: opts.SoftwareStatement, backendDomain: opts.BackendDomain,
		frontendDomain: opts.FrontendDomain, app: true,
	})
	if preparationErr != nil {
		return nil, preparationErr
	}
	if data.ApplicationType != string(existing.AppType) {
		return nil, exceptions.NewValidationError("application_type cannot be changed")
	}
	parsedClientURI, err := url.Parse(data.ClientURI)
	if err != nil {
		return nil, exceptions.NewValidationError("invalid client URI")
	}
	tokenEndpointAuthMethod, serviceErr := mapAuthMethod(data.TokenEndpointAuthMethod)
	if serviceErr != nil {
		return nil, serviceErr
	}
	scopesList := strings.Fields(data.Scope)
	stdScopes, customScopes, defaultStdScopes, defaultCustomScopes, serviceErr := mapScopesToStandardAndCustomScopes(scopesList, nil)
	if serviceErr != nil {
		return nil, serviceErr
	}
	params, serviceErr := s.mapAppRegistrationDataToDBParams(ctx, mapAppRegistrationDataToDBParamsOptions{
		appType: existing.AppType, accountPublicID: account.PublicID, accountID: opts.AccountID,
		domain: parsedClientURI.Hostname(), requestID: opts.RequestID, tokenEndpointAuthMethod: tokenEndpointAuthMethod,
		transport: existing.Transport, scopes: stdScopes, customScopes: customScopes, defaultScopes: defaultStdScopes,
		defaultCustomScopes: defaultCustomScopes, allowUserRegistration: existing.AllowUserRegistration,
		usernameColumn: existing.UsernameColumn, authProviders: existing.AuthProviders, data: &data,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	updated, err := s.database.UpdateRegisteredApp(ctx, database.UpdateRegisteredAppParams{
		ID: existing.ID, ClientName: params.ClientName, ClientUri: params.ClientUri, UsernameColumn: params.UsernameColumn,
		TokenEndpointAuthMethod: params.TokenEndpointAuthMethod, GrantTypes: params.GrantTypes, LogoUri: params.LogoUri,
		TosUri: params.TosUri, PolicyUri: params.PolicyUri, Contacts: params.Contacts, SoftwareID: params.SoftwareID,
		SoftwareVersion: params.SoftwareVersion, Scopes: params.Scopes, DefaultScopes: params.DefaultScopes,
		CustomScopes: params.CustomScopes, DefaultCustomScopes: params.DefaultCustomScopes, Domain: params.Domain,
		Transport: params.Transport, RedirectUris: params.RedirectUris, ResponseTypes: params.ResponseTypes,
		AllowUserRegistration: params.AllowUserRegistration, AuthProviders: params.AuthProviders, JwksUri: params.JwksUri,
		Jwks: params.Jwks, SectorIdentifierUri: params.SectorIdentifierUri, SubjectType: params.SubjectType,
		IDTokenSignedResponseAlg: params.IDTokenSignedResponseAlg, IDTokenEncryptedResponseAlg: params.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: params.IDTokenEncryptedResponseEnc, UserinfoSignedResponseAlg: params.UserinfoSignedResponseAlg,
		UserinfoEncryptedResponseAlg: params.UserinfoEncryptedResponseAlg, UserinfoEncryptedResponseEnc: params.UserinfoEncryptedResponseEnc,
		RequestObjectSigningAlg: params.RequestObjectSigningAlg, RequestObjectEncryptionAlg: params.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc: params.RequestObjectEncryptionEnc, TokenEndpointAuthSigningAlg: params.TokenEndpointAuthSigningAlg,
		DefaultMaxAge: params.DefaultMaxAge, RequireAuthTime: params.RequireAuthTime, DefaultAcrValues: params.DefaultAcrValues,
		InitiateLoginUri: params.InitiateLoginUri, RequestUris: params.RequestUris, AccessTokenSigningAlg: params.AccessTokenSigningAlg,
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to update app", "error", err)
		return nil, exceptions.FromDBError(err)
	}
	dto := dtos.MapRegisteredApp(&updated, opts.SoftwareStatement, currentSecret, exp, key)
	token, serviceErr := s.CreateAppCredentialsRegistrationAccessToken(ctx, CreateAppCredentialsRegistrationAccessTokenOptions{
		RequestID:       opts.RequestID,
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		ClientID:        updated.ClientID,
		BackendDomain:   opts.BackendDomain,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	issuer := dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain)
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(issuer, updated.ClientID))
	return dto.Registration, nil
}

func registrationDataFromAccountOptions(opts CreateAccountCredentialsRegistrationOptions) ApplicationRegistrationData {
	return ApplicationRegistrationData{
		RedirectURIs: opts.RedirectURIs, TokenEndpointAuthMethod: opts.TokenEndpointAuthMethod,
		ResponseTypes: opts.ResponseTypes, GrantTypes: opts.GrantTypes, ApplicationType: opts.ApplicationType,
		ClientName: opts.ClientName, ClientURI: opts.ClientURI, LogoURI: opts.LogoURI, Scope: opts.Scope,
		Contacts: opts.Contacts, TOSURI: opts.TOSURI, PolicyURI: opts.PolicyURI, JWKsURI: opts.JWKsURI, JWKs: opts.JWKs,
		SoftwareID: opts.SoftwareID, SoftwareVersion: opts.SoftwareVersion, SubjectType: opts.SubjectType,
		SectorIdentifierURI: opts.SectorIdentifierURI, DefaultMaxAge: opts.DefaultMaxAge, RequireAuthTime: opts.RequireAuthTime,
		DefaultACRValues: opts.DefaultACRValues, InitiateLoginURI: opts.InitiateLoginURI, RequestURIs: opts.RequestURIs,
		IDTokenSignedResponseAlg: opts.IDTokenSignedResponseAlg, IDTokenEncryptedResponseAlg: opts.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: opts.IDTokenEncryptedResponseEnc, UserInfoSignedResponseAlg: opts.UserInfoSignedResponseAlg,
		UserInfoEncryptedResponseAlg: opts.UserInfoEncryptedResponseAlg, UserInfoEncryptedResponseEnc: opts.UserInfoEncryptedResponseEnc,
		RequestObjectSigningAlg: opts.RequestObjectSigningAlg, RequestObjectEncryptionAlg: opts.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc: opts.RequestObjectEncryptionEnc, TokenEndpointAuthSigningAlg: opts.TokenEndpointAuthSigningAlg,
		AccessTokenSigningAlg: opts.AccessTokenSigningAlg,
	}
}

func registrationDataFromAppOptions(opts CreateAppCredentialsRegistrationOptions) ApplicationRegistrationData {
	return ApplicationRegistrationData{
		RedirectURIs: opts.RedirectURIs, TokenEndpointAuthMethod: opts.TokenEndpointAuthMethod,
		ResponseTypes: opts.ResponseTypes, GrantTypes: opts.GrantTypes, ApplicationType: opts.ApplicationType,
		ClientName: opts.ClientName, ClientURI: opts.ClientURI, LogoURI: opts.LogoURI, Scope: opts.Scope,
		Contacts: opts.Contacts, TOSURI: opts.TOSURI, PolicyURI: opts.PolicyURI, JWKsURI: opts.JWKsURI, JWKs: opts.JWKs,
		SoftwareID: opts.SoftwareID, SoftwareVersion: opts.SoftwareVersion, SubjectType: opts.SubjectType,
		SectorIdentifierURI: opts.SectorIdentifierURI, DefaultMaxAge: opts.DefaultMaxAge, RequireAuthTime: opts.RequireAuthTime,
		DefaultACRValues: opts.DefaultACRValues, InitiateLoginURI: opts.InitiateLoginURI, RequestURIs: opts.RequestURIs,
		IDTokenSignedResponseAlg: opts.IDTokenSignedResponseAlg, IDTokenEncryptedResponseAlg: opts.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc: opts.IDTokenEncryptedResponseEnc, UserInfoSignedResponseAlg: opts.UserInfoSignedResponseAlg,
		UserInfoEncryptedResponseAlg: opts.UserInfoEncryptedResponseAlg, UserInfoEncryptedResponseEnc: opts.UserInfoEncryptedResponseEnc,
		RequestObjectSigningAlg: opts.RequestObjectSigningAlg, RequestObjectEncryptionAlg: opts.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc: opts.RequestObjectEncryptionEnc, TokenEndpointAuthSigningAlg: opts.TokenEndpointAuthSigningAlg,
		AccessTokenSigningAlg: opts.AccessTokenSigningAlg,
	}
}
