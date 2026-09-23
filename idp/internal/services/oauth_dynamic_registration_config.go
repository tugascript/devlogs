package services

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const oauthDynamicRegistrationConfigLocation = "oauth_dynamic_registration_config"

type GetRegisteredClientOptions struct {
	RegistrationToken string
	RequestID         string
	AccountPublicID   uuid.UUID
	ClientID          string
	BackendDomain     string
	HostUsername      string
}

func (s *Services) getActiveAccountCredentialSecretAndKey(
	ctx context.Context,
	requestID string,
	row *database.AccountCredential,
) (string, time.Time, utils.JWK, *exceptions.ServiceError) {
	switch row.TokenEndpointAuthMethod {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		secretEnt, err := s.database.FindCurrentAccountCredentialSecretByAccountCredentialID(ctx, row.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.replaceRegistrationSecret(ctx, requestID, row.AccountID, row.AccountPublicID, row.ID, false)
		}
		if err != nil {
			return "", time.Time{}, nil, exceptions.FromDBError(err)
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
		if row.JwksUri.Valid || len(row.Jwks) > 0 {
			return "", time.Time{}, nil, nil
		}
		keyEnt, err := s.database.FindCurrentAccountCredentialKeyByAccountCredentialID(ctx, row.ID)
		if err != nil {
			return "", time.Time{}, nil, exceptions.FromDBError(err)
		}
		key, serviceErr := s.registrationPrivateKey(ctx, requestID, keyEnt)
		return "", keyEnt.ExpiresAt, key, serviceErr
	default:
		return "", time.Time{}, nil, nil
	}
}

func (s *Services) getActiveAppSecretAndKey(
	ctx context.Context,
	requestID string,
	row *database.App,
) (string, time.Time, utils.JWK, *exceptions.ServiceError) {
	switch row.TokenEndpointAuthMethod {
	case database.AuthMethodClientSecretBasic, database.AuthMethodClientSecretPost, database.AuthMethodClientSecretJwt:
		activeSecret, err := s.database.FindCurrentAppSecret(ctx, row.ID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.replaceRegistrationSecret(ctx, requestID, row.AccountID, row.AccountPublicID, row.ID, true)
		}
		if err != nil {
			return "", time.Time{}, nil, exceptions.FromDBError(err)
		}
		decryptedSecret, decryptErr := s.crypto.DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
			RequestID: requestID,
			GetDecryptDEKfn: s.BuildGetDecAccountDEKFn(ctx, BuildGetDecAccountDEKFnOptions{
				RequestID: requestID,
				AccountID: row.AccountID,
			}),
			GetEncryptDEKfn: s.BuildGetEncAccountDEKfn(ctx, BuildGetEncAccountDEKOptions{
				RequestID: requestID,
				AccountID: row.AccountID,
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
		if row.JwksUri.Valid || len(row.Jwks) > 0 {
			return "", time.Time{}, nil, nil
		}
		keyEnt, err := s.database.FindCurrentAppKey(ctx, row.ID)
		if err != nil {
			return "", time.Time{}, nil, exceptions.FromDBError(err)
		}
		key, serviceErr := s.registrationPrivateKey(ctx, requestID, keyEnt)
		return "", keyEnt.ExpiresAt, key, serviceErr
	default:
		return "", time.Time{}, nil, nil
	}
}

func (s *Services) GetRegisteredAccountCredentials(ctx context.Context, opts GetRegisteredClientOptions) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	return s.getRegisteredAccountCredentials(ctx, opts)
}

func (s *Services) getRegisteredAccountCredentials(
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
		row,
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
	token, serviceErr := s.registrationResponseToken(ctx, registrationStateOptions{
		RequestID: opts.RequestID, AccountPublicID: opts.AccountPublicID, AccountVersion: account.Version(),
		ClientID: row.ClientID, BackendDomain: opts.BackendDomain, ID: row.ID, AccountID: row.AccountID,
		Statement: row.SoftwareStatement, Stored: row.RegistrationTokenJti, Token: opts.RegistrationToken, App: false,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(row, row.SoftwareStatement, secret, exp, key)
	if serviceErr != nil {
		return nil, exceptions.NewUnauthorizedError()
	}
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(opts.BackendDomain, row.ClientID))
	return dto.Registration, nil
}

func (s *Services) GetRegisteredApp(ctx context.Context, opts GetRegisteredClientOptions) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	return s.getRegisteredApp(ctx, opts)
}

func (s *Services) getRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	row, serviceErr := s.findRegisteredApp(ctx, opts)
	if serviceErr != nil {
		return nil, serviceErr
	}
	secret, exp, key, serviceErr := s.getActiveAppSecretAndKey(
		ctx, opts.RequestID, row,
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
	token, serviceErr := s.registrationResponseToken(ctx, registrationStateOptions{
		RequestID: opts.RequestID, AccountPublicID: opts.AccountPublicID, AccountVersion: account.Version(),
		ClientID: row.ClientID, BackendDomain: opts.BackendDomain, ID: row.ID, AccountID: row.AccountID,
		Statement: row.SoftwareStatement, Stored: row.RegistrationTokenJti, Token: opts.RegistrationToken, App: true,
		HostUsername: opts.HostUsername,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto := dtos.MapRegisteredApp(row, row.SoftwareStatement, secret, exp, key)
	issuer := dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain)
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(issuer, row.ClientID))
	return dto.Registration, nil
}

func (s *Services) DeleteRegisteredAccountCredentials(ctx context.Context, opts GetRegisteredClientOptions) *exceptions.ServiceError {
	_, err := registrationTransaction(s, ctx, opts.RequestID, func(qrs *database.Queries) (struct{}, *exceptions.ServiceError) {
		return struct{}{}, s.deleteRegisteredAccountCredentials(ctx, qrs, opts)
	})
	if err == nil {
		if cacheErr := s.cache.DeleteResponse(ctx, cache.DeleteResponseOptions{RequestID: opts.RequestID, Key: fmt.Sprintf("%s:%s", accountCredentialsKeysCacheKeyPrefix, opts.AccountPublicID)}); cacheErr != nil {
			s.logger.WarnContext(ctx, "Failed to invalidate deleted client key discovery cache", "error", cacheErr)
		}
	}
	return err
}
func (s *Services) deleteRegisteredAccountCredentials(
	ctx context.Context,
	qrs *database.Queries,
	opts GetRegisteredClientOptions,
) *exceptions.ServiceError {
	row, serviceErr := s.findRegisteredAccountCredential(ctx, opts)
	if serviceErr != nil {
		return serviceErr
	}
	// The middleware authenticated before the lock; check state again under it.
	var authErr *exceptions.ServiceError
	_, _, authErr = s.ProcessAccountCredentialsRegistrationAccessToken(ctx, ProcessAccountCredentialsRegistrationAccessTokenOptions{AuthHeader: "Bearer " + opts.RegistrationToken, IssuerDomain: opts.BackendDomain, RequestID: opts.RequestID})
	if authErr != nil {
		return authErr
	}
	if err := qrs.RevokeRegisteredAccountCredentialsSecrets(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	if err := qrs.RevokeRegisteredAccountCredentialsKeys(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	if err := qrs.DeleteRegisteredAccountCredentialsGrants(ctx, database.DeleteRegisteredAccountCredentialsGrantsParams{AccountID: row.AccountID, GrantedClientID: row.ClientID}); err != nil {
		return exceptions.FromDBError(err)
	}

	if err := qrs.DeleteAccountCredentials(ctx, opts.ClientID); err != nil {
		return exceptions.FromDBError(err)
	}
	return nil
}

func (s *Services) DeleteRegisteredApp(ctx context.Context, opts GetRegisteredClientOptions) *exceptions.ServiceError {
	_, err := registrationTransaction(s, ctx, opts.RequestID, func(qrs *database.Queries) (struct{}, *exceptions.ServiceError) {
		return struct{}{}, s.deleteRegisteredApp(ctx, qrs, opts)
	})
	return err
}
func (s *Services) deleteRegisteredApp(
	ctx context.Context,
	qrs *database.Queries,
	opts GetRegisteredClientOptions,
) *exceptions.ServiceError {
	row, serviceErr := s.findRegisteredApp(ctx, opts)
	if serviceErr != nil {
		return serviceErr
	}
	// The middleware authenticated before the lock; check state again under it.
	var authErr *exceptions.ServiceError
	_, _, authErr = s.ProcessAppDynamicRegistrationAccessToken(ctx, ProcessAppDynamicRegistrationAccessTokenOptions{AuthHeader: "Bearer " + opts.RegistrationToken, AccountID: row.AccountID, IssuerDomain: dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain), RequestID: opts.RequestID})
	if authErr != nil {
		return authErr
	}
	if err := qrs.RevokeRegisteredAppSecrets(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	if err := qrs.RevokeRegisteredAppKeys(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	if err := qrs.DeleteRegisteredAppGrants(ctx, database.DeleteRegisteredAppGrantsParams{AccountID: row.AccountID, GrantedClientID: row.ClientID}); err != nil {
		return exceptions.FromDBError(err)
	}

	if err := qrs.DeleteApp(ctx, row.ID); err != nil {
		return exceptions.FromDBError(err)
	}
	return nil
}

func (s *Services) findRegisteredAccountCredential(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*database.AccountCredential, *exceptions.ServiceError) {
	row, err := s.database.LockRegisteredAccountCredentials(ctx, database.LockRegisteredAccountCredentialsParams{
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.ClientID,
	})
	if err != nil {
		return nil, registrationLookupError(err)
	}
	return &row, nil
}

func (s *Services) findRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*database.App, *exceptions.ServiceError) {
	row, err := s.database.LockRegisteredApp(ctx, database.LockRegisteredAppParams{
		AccountPublicID: opts.AccountPublicID,
		ClientID:        opts.ClientID,
	})
	if err != nil {
		return nil, registrationLookupError(err)
	}
	return &row, nil
}

type UpdateRegisteredClientOptions struct {
	CreateAccountCredentialsRegistrationOptions
	ClientID                     string
	SubmittedClientID            string
	SubmittedClientSecret        string
	SubmittedClientSecretPresent bool
	RegistrationToken            string
}

func (s *Services) UpdateRegisteredAccountCredentials(ctx context.Context, opts UpdateRegisteredClientOptions) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	return registrationTransaction(s, ctx, opts.RequestID, func(qrs *database.Queries) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
		return s.updateRegisteredAccountCredentials(ctx, qrs, opts)
	})
}

func (s *Services) updateRegisteredAccountCredentials(
	ctx context.Context,
	qrs *database.Queries,
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
		existing,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	if opts.SubmittedClientSecretPresent || opts.SubmittedClientSecret != "" {
		if currentSecret == "" || subtle.ConstantTimeCompare([]byte(opts.SubmittedClientSecret), []byte(currentSecret)) != 1 {
			return nil, exceptions.NewError(exceptions.OAuthErrorInvalidClientMetadata, "invalid client secret")
		}
	}
	data := registrationDataFromAccountOptions(opts.CreateAccountCredentialsRegistrationOptions)
	if data.TokenEndpointAuthMethod != "" && data.TokenEndpointAuthMethod != string(existing.TokenEndpointAuthMethod) {
		return nil, exceptions.NewValidationError("token_endpoint_auth_method cannot be changed")
	}
	data.TokenEndpointAuthMethod = string(existing.TokenEndpointAuthMethod)
	data.ApplicationType = string(existing.CredentialsType)
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountPublicID: opts.AccountPublicID, data: data,
		softwareStatement: opts.SoftwareStatement, backendDomain: opts.BackendDomain,
		frontendDomain: opts.FrontendDomain, app: false,
	})
	if preparationErr != nil {
		return nil, preparationErr
	}
	if data.TokenEndpointAuthMethod != string(existing.TokenEndpointAuthMethod) {
		return nil, exceptions.NewValidationError("token_endpoint_auth_method cannot be changed")
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
	updated, err := qrs.UpdateRegisteredAccountCredentials(ctx, database.UpdateRegisteredAccountCredentialsParams{
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
	token, serviceErr := s.registrationResponseToken(ctx, registrationStateOptions{
		RequestID: opts.RequestID, AccountPublicID: opts.AccountPublicID, AccountVersion: opts.AccountVersion,
		ClientID: updated.ClientID, BackendDomain: opts.BackendDomain, ID: updated.ID, AccountID: updated.AccountID,
		Statement: opts.SoftwareStatement, Stored: existing.RegistrationTokenJti, Token: opts.RegistrationToken, App: false,
	})
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto.Registration.WithRegistrationAccess(token, dtos.RegistrationClientURI(opts.BackendDomain, updated.ClientID))
	return dto.Registration, nil
}

type UpdateRegisteredAppOptions struct {
	CreateAppCredentialsRegistrationOptions
	ClientID                     string
	SubmittedClientID            string
	SubmittedClientSecret        string
	SubmittedClientSecretPresent bool
	RegistrationToken            string
	HostUsername                 string
}

func (s *Services) UpdateRegisteredApp(ctx context.Context, opts UpdateRegisteredAppOptions) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	return registrationTransaction(s, ctx, opts.RequestID, func(qrs *database.Queries) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
		return s.updateRegisteredApp(ctx, qrs, opts)
	})
}

func (s *Services) updateRegisteredApp(
	ctx context.Context,
	qrs *database.Queries,
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
		ctx, opts.RequestID, existing,
	)
	if serviceErr != nil {
		return nil, serviceErr
	}
	if opts.SubmittedClientSecretPresent || opts.SubmittedClientSecret != "" {
		if currentSecret == "" || subtle.ConstantTimeCompare([]byte(opts.SubmittedClientSecret), []byte(currentSecret)) != 1 {
			return nil, exceptions.NewError(exceptions.OAuthErrorInvalidClientMetadata, "invalid client secret")
		}
	}
	data := registrationDataFromAppOptions(opts.CreateAppCredentialsRegistrationOptions)
	if data.TokenEndpointAuthMethod != "" && data.TokenEndpointAuthMethod != string(existing.TokenEndpointAuthMethod) {
		return nil, exceptions.NewValidationError("token_endpoint_auth_method cannot be changed")
	}
	data.TokenEndpointAuthMethod = string(existing.TokenEndpointAuthMethod)
	data.ApplicationType = string(existing.AppType)
	data, preparationErr := s.prepareDynamicRegistration(ctx, prepareDynamicRegistrationOptions{
		requestID: opts.RequestID, accountID: opts.AccountID, data: data,
		softwareStatement: opts.SoftwareStatement, backendDomain: opts.BackendDomain,
		frontendDomain: opts.FrontendDomain, app: true,
	})
	if preparationErr != nil {
		return nil, preparationErr
	}
	if data.TokenEndpointAuthMethod != string(existing.TokenEndpointAuthMethod) {
		return nil, exceptions.NewValidationError("token_endpoint_auth_method cannot be changed")
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
	updated, err := qrs.UpdateRegisteredApp(ctx, database.UpdateRegisteredAppParams{
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
	token, serviceErr := s.registrationResponseToken(ctx, registrationStateOptions{
		RequestID: opts.RequestID, AccountPublicID: account.PublicID, AccountVersion: account.Version(),
		ClientID: updated.ClientID, BackendDomain: opts.BackendDomain, ID: updated.ID, AccountID: updated.AccountID,
		Statement: opts.SoftwareStatement, Stored: existing.RegistrationTokenJti, Token: opts.RegistrationToken, App: true,
		HostUsername: opts.HostUsername,
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
