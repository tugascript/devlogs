package services

import (
	"context"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

const oauthDynamicRegistrationConfigLocation = "oauth_dynamic_registration_config"

type GetRegisteredClientOptions struct {
	RequestID       string
	AccountPublicID uuid.UUID
	ClientID        string
	BackendDomain   string
	HostUsername    string
}

func (s *Services) GetRegisteredAccountCredentials(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	row, serviceErr := s.findRegisteredAccountCredential(ctx, opts)
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(row, "", "", row.CreatedAt, nil)
	if serviceErr != nil {
		return nil, exceptions.NewUnauthorizedError()
	}
	dto.Registration.WithRegistrationAccess("", dtos.RegistrationClientURI(opts.BackendDomain, row.ClientID))
	return dto.Registration.WithoutSecrets(), nil
}

func (s *Services) GetRegisteredApp(
	ctx context.Context,
	opts GetRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	row, serviceErr := s.findRegisteredApp(ctx, opts)
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto := dtos.MapRegisteredApp(row, "", "", row.CreatedAt, nil)
	issuer := dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain)
	dto.Registration.WithRegistrationAccess("", dtos.RegistrationClientURI(issuer, row.ClientID))
	return dto.Registration.WithoutSecrets(), nil
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
		return nil, exceptions.NewUnauthorizedError()
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
		return nil, exceptions.NewUnauthorizedError()
	}
	return &row, nil
}

type UpdateRegisteredClientOptions struct {
	CreateAccountCredentialsRegistrationOptions
	ClientID string
}

func (s *Services) UpdateRegisteredAccountCredentials(
	ctx context.Context,
	opts UpdateRegisteredClientOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationConfigLocation, "UpdateRegisteredAccountCredentials")
	existing, serviceErr := s.findRegisteredAccountCredential(ctx, GetRegisteredClientOptions{
		RequestID: opts.RequestID, AccountPublicID: opts.AccountPublicID, ClientID: opts.ClientID,
	})
	if serviceErr != nil {
		return nil, serviceErr
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
	dto, serviceErr := dtos.MapRegisteredAccountCredentials(&updated, opts.SoftwareStatement, "", updated.CreatedAt, nil)
	if serviceErr != nil {
		return nil, serviceErr
	}
	dto.Registration.WithRegistrationAccess("", dtos.RegistrationClientURI(opts.BackendDomain, updated.ClientID))
	return dto.Registration.WithoutSecrets(), nil
}

type UpdateRegisteredAppOptions struct {
	CreateAppCredentialsRegistrationOptions
	ClientID     string
	HostUsername string
}

func (s *Services) UpdateRegisteredApp(
	ctx context.Context,
	opts UpdateRegisteredAppOptions,
) (*dtos.ClientRegistrationDTO, *exceptions.ServiceError) {
	logger := s.buildLogger(opts.RequestID, oauthDynamicRegistrationConfigLocation, "UpdateRegisteredApp")
	account, serviceErr := s.GetAccountByID(ctx, GetAccountByIDOptions{RequestID: opts.RequestID, ID: opts.AccountID})
	if serviceErr != nil {
		return nil, exceptions.NewUnauthorizedError()
	}
	existing, serviceErr := s.findRegisteredApp(ctx, GetRegisteredClientOptions{
		RequestID: opts.RequestID, AccountPublicID: account.PublicID, ClientID: opts.ClientID,
	})
	if serviceErr != nil {
		return nil, serviceErr
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
	dto := dtos.MapRegisteredApp(&updated, opts.SoftwareStatement, "", updated.CreatedAt, nil)
	issuer := dynamicRegistrationIssuerDomain(opts.HostUsername, opts.BackendDomain)
	dto.Registration.WithRegistrationAccess("", dtos.RegistrationClientURI(issuer, updated.ClientID))
	return dto.Registration.WithoutSecrets(), nil
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
