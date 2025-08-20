// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func accountCredentialsCleanUp(t *testing.T) func() {
	return func() {
		db := GetTestDatabase(t)

		if err := db.DeleteAllAccountCredentials(context.Background()); err != nil {
			t.Fatal("Failed to delete all account credentials", err)
		}
		if err := db.DeleteAllCredentialsKeys(context.Background()); err != nil {
			t.Fatal("Failed to delete all credentials keys", err)
		}
		if err := db.DeleteAllCredentialsSecrets(context.Background()); err != nil {
			t.Fatal("Failed to delete all credentials secrets", err)
		}
		if err := db.DeleteAllAccounts(context.Background()); err != nil {
			t.Fatal("Failed to delete all accounts", err)
		}
	}
}

func TestCreateAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	testCases := []TestRequestCase[bodies.CreateAccountCredentialsBody]{
		{
			Name: "Should create service credentials with client_secret_jwt",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "admin-service",
					Scopes:                  []string{"account:admin"},
					TokenEndpointAuthMethod: "client_secret_jwt",
					Transport:               "https",
					ClientURI:               "https://admin.example.com",
					SoftwareID:              "admin-service",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodClientSecretJwt)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeService)
				AssertEqual(t, resBody.Transport, database.TransportHttps)
			},
		},
		{
			Name: "Should create service credentials with private_key_jwt and ES256",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "super-service",
					Scopes:                  []string{"account:credentials:read", "account:credentials:write"},
					TokenEndpointAuthMethod: "private_key_jwt",
					Transport:               "https",
					ClientURI:               "https://super.example.com",
					SoftwareID:              "super-service",
					SoftwareVersion:         "2.0.0",
					Algorithm:               "ES256",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodPrivateKeyJwt)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeService)
			},
		},
		{
			Name: "Should create service credentials with private_key_jwt and EdDSA",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "eddsa-service",
					Scopes:                  []string{"account:credentials:read", "account:credentials:write"},
					TokenEndpointAuthMethod: "private_key_jwt",
					Transport:               "https",
					ClientURI:               "https://eddsa.example.com",
					SoftwareID:              "eddsa-service",
					SoftwareVersion:         "1.0.0",
					Algorithm:               "EdDSA",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodPrivateKeyJwt)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeService)
			},
		},
		{
			Name: "Should create service credentials with client_secret_post",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "app-service",
					Scopes:                  []string{"account:apps:read", "account:apps:write"},
					TokenEndpointAuthMethod: "client_secret_post",
					Transport:               "https",
					ClientURI:               "https://app.example.com",
					SoftwareID:              "app-service",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodClientSecretPost)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeService)
			},
		},
		{
			Name: "Should create service credentials with client_secret_basic",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "user-service",
					Scopes:                  []string{"account:users:read", "account:users:write"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Transport:               "https",
					ClientURI:               "https://user.example.com",
					SoftwareID:              "user-service",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodClientSecretBasic)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeService)
			},
		},
		{
			Name: "Should create MCP credentials with streamable_http transport",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "mcp",
					Name:                    "mcp-client",
					Scopes:                  []string{"account:admin"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Transport:               "streamable_http",
					ClientURI:               "https://mcp.example.com",
					SoftwareID:              "mcp-client",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodClientSecretBasic)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeMcp)
				AssertEqual(t, resBody.Transport, database.TransportStreamableHttp)
			},
		},
		{
			Name: "Should create MCP credentials with stdio transport",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "mcp",
					Name:                    "mcp-stdio",
					Scopes:                  []string{"account:admin"},
					TokenEndpointAuthMethod: "private_key_jwt",
					Transport:               "stdio",
					ClientURI:               "https://mcp-stdio.example.com",
					SoftwareID:              "mcp-stdio",
					SoftwareVersion:         "1.0.0",
					Algorithm:               "ES256",
				}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodPrivateKeyJwt)
				AssertEqual(t, resBody.Type, database.AccountCredentialsTypeMcp)
				AssertEqual(t, resBody.Transport, database.TransportStdio)
			},
		},
		{
			Name: "Should reject native credentials creation",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "native",
					Name:                    "native-client",
					Scopes:                  []string{"account:admin"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Transport:               "https",
					ClientURI:               "https://native.example.com",
					SoftwareID:              "native-client",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Native credentials are not supported")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST with invalid data",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "",
					Scopes:                  []string{"invalid:scope", "account:users:readsd"},
					TokenEndpointAuthMethod: "invalid_auth_method",
					Transport:               "invalid_transport",
					ClientURI:               "not-a-uri",
					SoftwareID:              "",
					SoftwareVersion:         "",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, len(resBody.Fields) >= 5, true)
			},
		},
		{
			Name: "Should return 409 CONFLICT with existing name",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)

				// Create initial credentials
				if _, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "existing-name",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://existing.example.com",
					SoftwareID:      "existing-service",
					SoftwareVersion: "1.0.0",
				}); err != nil {
					t.Fatal("Failed to create initial account credentials", err)
				}

				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "existing-name",
					Scopes:                  []string{"account:admin"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Transport:               "https",
					ClientURI:               "https://new.example.com",
					SoftwareID:              "new-service",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Account credentials name already exists")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "unauthorized-service",
					Scopes:                  []string{"account:credentials:write", "account:auth_providers:read"},
					TokenEndpointAuthMethod: "client_secret_basic",
					Transport:               "https",
					ClientURI:               "https://unauthorized.example.com",
					SoftwareID:              "unauthorized-service",
					SoftwareVersion:         "1.0.0",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.CreateAccountCredentialsBody],
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:write scope",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})
				return bodies.CreateAccountCredentialsBody{
					Type:                    "service",
					Name:                    "forbidden-service",
					Scopes:                  []string{"account:apps:read", "account:apps:write"},
					TokenEndpointAuthMethod: "client_secret_post",
					Transport:               "https",
					ClientURI:               "https://forbidden.example.com",
					SoftwareID:              "forbidden-service",
					SoftwareVersion:         "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.CreateAccountCredentialsBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, accountCredentialsPath, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestUpdateAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	updateAccountCredentialBeforeEach := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "update-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      "client_secret_basic",
			Transport:       "https",
			ClientURI:       "https://update.example.com",
			SoftwareID:      "update-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create initial account credentials: %v", err)
		}
		clientID = cred.ClientID
		return accessToken
	}

	testCases := []TestRequestCase[bodies.UpdateAccountCredentialsBody]{
		{
			Name: "Should update service credentials name and scopes",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				accessToken := updateAccountCredentialBeforeEach(t)
				return bodies.UpdateAccountCredentialsBody{
					Name:            "updated-service-name",
					Scopes:          []string{"account:users:read"},
					Transport:       "https",
					ClientURI:       "https://updated.example.com",
					SoftwareVersion: "2.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertEqual(t, resBody.Name, "updated-service-name")
				AssertEqual(t, len(resBody.Scopes), 1)
				AssertEqual(t, resBody.Scopes[0], "account:users:read")
				AssertEqual(t, resBody.SoftwareVersion, "2.0.0")
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should update MCP credentials scopes and software version",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

				// Create MCP credentials first
				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "mcp",
					Name:            "mcp-update",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "streamable_http",
					ClientURI:       "https://mcp-update.example.com",
					SoftwareID:      "mcp-update",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create MCP credentials: %v", err)
				}
				clientID = cred.ClientID

				return bodies.UpdateAccountCredentialsBody{
					Name:            "updated-mcp-name",
					Scopes:          []string{"account:users:read", "account:apps:read"},
					ClientURI:       "https://updated-mcp.example.com",
					SoftwareVersion: "2.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertEqual(t, resBody.Name, "updated-mcp-name")
				AssertEqual(t, len(resBody.Scopes), 2)
				AssertEqual(t, resBody.Scopes[0], "account:users:read")
				AssertEqual(t, resBody.Scopes[1], "account:apps:read")
				AssertEqual(t, resBody.SoftwareVersion, "2.0.0")
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 400 BAD REQUEST with invalid data",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				accessToken := updateAccountCredentialBeforeEach(t)
				return bodies.UpdateAccountCredentialsBody{
					Name:            "",
					Scopes:          []string{"account:users:read", "invalid:scope"},
					Transport:       "invalid_transport",
					ClientURI:       "not-a-uri",
					SoftwareVersion: "",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, len(resBody.Fields) >= 3, true)
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 409 CONFLICT with existing name",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

				// Create first credentials
				if _, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "existing-name",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://existing.example.com",
					SoftwareID:      "existing-service",
					SoftwareVersion: "1.0.0",
				}); err != nil {
					t.Fatalf("Failed to create first credentials: %v", err)
				}

				// Create second credentials to update
				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "other-name",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://other.example.com",
					SoftwareID:      "other-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create second credentials: %v", err)
				}
				clientID = cred.ClientID

				return bodies.UpdateAccountCredentialsBody{
					Name:            "existing-name",
					Scopes:          []string{"account:users:read"},
					Transport:       "https",
					ClientURI:       "https://updated.example.com",
					SoftwareVersion: "2.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Account credentials name already exists")
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				return bodies.UpdateAccountCredentialsBody{
					Name:            "new-name",
					Scopes:          []string{"account:users:read"},
					Transport:       "https",
					ClientURI:       "https://new.example.com",
					SoftwareVersion: "1.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.UpdateAccountCredentialsBody],
			PathFn: func() string {
				return accountCredentialsPath + "/" + utils.Base62UUID()
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				updateAccountCredentialBeforeEach(t)
				return bodies.UpdateAccountCredentialsBody{
					Name:            "updated-name",
					Scopes:          []string{"account:users:read"},
					Transport:       "https",
					ClientURI:       "https://updated.example.com",
					SoftwareVersion: "2.0.0",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.UpdateAccountCredentialsBody],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:write scope",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-update",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden.example.com",
					SoftwareID:      "forbidden-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create credentials: %v", err)
				}
				clientID = cred.ClientID

				return bodies.UpdateAccountCredentialsBody{
					Name:            "updated-name",
					Scopes:          []string{"account:users:read"},
					Transport:       "https",
					ClientURI:       "https://updated.example.com",
					SoftwareVersion: "2.0.0",
				}, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.UpdateAccountCredentialsBody],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPut, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestListAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	listAccountBeforeEach := func(t *testing.T, n int) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		types := []string{"service", "mcp"}
		authMethods := []string{"client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt"}
		transports := []string{"https", "streamable_http", "stdio"}

		for i := 0; i < n; i++ {
			credType := types[i%len(types)]
			authMethod := authMethods[i%len(authMethods)]
			transport := transports[i%len(transports)]
			name := "cred-" + uuid.NewString()

			_, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
				RequestID:       uuid.NewString(),
				AccountPublicID: account.PublicID,
				AccountVersion:  account.Version(),
				CredentialsType: credType,
				Name:            name,
				Scopes:          []string{"account:admin"},
				AuthMethod:      authMethod,
				Transport:       transport,
				ClientURI:       "https://" + name + ".example.com",
				SoftwareID:      name + "-service",
				SoftwareVersion: "1.0.0",
			})
			if err != nil {
				t.Fatalf("Failed to create account credentials: %v", err)
			}
		}

		return accessToken
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK without any account credentials",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AccountCredentialsDTO]{})
				AssertEqual(t, len(resBody.Items), 0)
				AssertEmpty(t, resBody.Next)
				AssertEmpty(t, resBody.Previous)
				AssertEqual(t, resBody.Total, 0)
			},
			Path: accountCredentialsPath,
		},
		{
			Name: "Should return 200 OK with paginated account credentials",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountBeforeEach(t, 30)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AccountCredentialsDTO]{})
				AssertEqual(t, len(resBody.Items), 20)
				AssertEqual(t, resBody.Total, 30)
				AssertNotEmpty(t, resBody.Next)
				AssertEmpty(t, resBody.Previous)
			},
			Path: accountCredentialsPath,
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			Path:      accountCredentialsPath,
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			Path:      accountCredentialsPath,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, tc.Path, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestGetSingleAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	getAccountCredentialBeforeEach := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "get-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      "client_secret_basic",
			Transport:       "https",
			ClientURI:       "https://get.example.com",
			SoftwareID:      "get-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		return accessToken
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with account credential",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := getAccountCredentialBeforeEach(t)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.Name)
				AssertEqual(t, resBody.TokenEndpointAuthMethod, database.AuthMethodClientSecretBasic)
				AssertEmpty(t, resBody.ClientSecret)
				AssertEmpty(t, resBody.ClientSecretJWK)
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + utils.Base62UUID()
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				getAccountCredentialBeforeEach(t)
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-cred",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden.example.com",
					SoftwareID:      "forbidden-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestDeleteAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	deleteAccountCredentialBeforeEach := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "delete-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      "client_secret_basic",
			Transport:       "https",
			ClientURI:       "https://delete.example.com",
			SoftwareID:      "delete-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		return accessToken
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 204 NO CONTENT on successful delete",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := deleteAccountCredentialBeforeEach(t)
				return nil, accessToken
			},
			ExpStatus: http.StatusNoContent,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				AssertEqual(t, res.StatusCode, http.StatusNoContent)
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + utils.Base62UUID()
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				deleteAccountCredentialBeforeEach(t)
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-delete",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden-delete.example.com",
					SoftwareID:      "forbidden-delete-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodDelete, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestListAccountCredentialsSecrets(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	listAccountCredentialBeforeEach := func(t *testing.T, authMethods string) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "list-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      authMethods,
			Transport:       "https",
			ClientURI:       "https://list.example.com",
			SoftwareID:      "list-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		return accessToken
	}

	pathFN := func() string {
		return accountCredentialsPath + "/" + clientID + "/secrets"
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with secrets for client_secret_post",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.ClientCredentialsSecretDTO]{})
				AssertEqual(t, resBody.Total > 0, true)
				AssertNotEmpty(t, resBody.Items[0].PublicID)
				AssertEqual(t, resBody.Items[0].Status, "active")
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 200 OK with keys for private_key_jwt",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountCredentialBeforeEach(t, "private_key_jwt")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.ClientCredentialsSecretDTO]{})
				AssertEqual(t, resBody.Total > 0, true)
				AssertNotEmpty(t, resBody.Items[0].PublicID)
				AssertEqual(t, resBody.Items[0].Status, "active")
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountCredentialBeforeEach(t, "client_secret_post")
				clientID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				listAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-list",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden-list.example.com",
					SoftwareID:      "forbidden-list-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn:    pathFN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestCreateAccountCredentialsSecret(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	createAccountCredentialBeforeEach := func(t *testing.T, authMethods string) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(
			context.Background(),
			services.CreateAccountCredentialsOptions{
				RequestID:       uuid.NewString(),
				AccountPublicID: account.PublicID,
				AccountVersion:  account.Version(),
				CredentialsType: "service",
				Name:            "create-secret-cred",
				Scopes:          []string{"account:admin"},
				AuthMethod:      authMethods,
				Transport:       "https",
				ClientURI:       "https://create-secret.example.com",
				SoftwareID:      "create-secret-service",
				SoftwareVersion: "1.0.0",
			},
		)
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}

		clientID = cred.ClientID
		return accessToken
	}

	pathFN := func() string {
		return accountCredentialsPath + "/" + clientID + "/secrets"
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 201 CREATED and create new secret for client_secret_post",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := createAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertNotEmpty(t, resBody.PublicID)
				AssertEqual(t, resBody.Status, "active")
				AssertNotEmpty(t, resBody.ClientSecret)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 201 CREATED and create new key for private_key_jwt",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := createAccountCredentialBeforeEach(t, "private_key_jwt")
				return nil, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertNotEmpty(t, resBody.PublicID)
				AssertEqual(t, resBody.Status, "active")
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := createAccountCredentialBeforeEach(t, "client_secret_post")
				clientID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				createAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-create-secret",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden-create-secret.example.com",
					SoftwareID:      "forbidden-create-secret-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn:    pathFN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPost, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestGetAccountCredentialsSecret(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID, secretID string
	getAccountCredentialSecretBeforeEach := func(t *testing.T, authMethods string) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "get-secret-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      authMethods,
			Transport:       "https",
			ClientURI:       "https://get-secret.example.com",
			SoftwareID:      "get-secret-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		secretID = cred.ClientSecretID
		return accessToken
	}

	pathFN := func() string {
		return accountCredentialsPath + "/" + clientID + "/secrets/" + secretID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with secret for client_secret_post",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := getAccountCredentialSecretBeforeEach(t, "client_secret_post")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertEqual(t, resBody.PublicID, secretID)
				AssertEqual(t, resBody.Status, "active")
				AssertEmpty(t, resBody.ClientSecret)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 200 OK with key for private_key_jwt",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := getAccountCredentialSecretBeforeEach(t, "private_key_jwt")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertEqual(t, resBody.PublicID, secretID)
				AssertEqual(t, resBody.Status, "active")
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := getAccountCredentialSecretBeforeEach(t, "client_secret_post")
				clientID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent secret",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := getAccountCredentialSecretBeforeEach(t, "client_secret_basic")
				secretID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				getAccountCredentialSecretBeforeEach(t, "client_secret_post")
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-get-secret",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden-get-secret.example.com",
					SoftwareID:      "forbidden-get-secret-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				secretID = cred.ClientSecretID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn:    pathFN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}

func TestRevokeAccountCredentialsSecret(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	var secretID string
	revokeAccountCredentialBeforeEach := func(t *testing.T, authMethods string) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			CredentialsType: "service",
			Name:            "revoke-cred",
			Scopes:          []string{"account:admin"},
			AuthMethod:      authMethods,
			Transport:       "https",
			ClientURI:       "https://revoke.example.com",
			SoftwareID:      "revoke-service",
			SoftwareVersion: "1.0.0",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		secretID = cred.ClientSecretID
		return accessToken
	}

	pathFN := func() string {
		return accountCredentialsPath + "/" + clientID + "/secrets/" + secretID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK on successful secret revoke for client_secret_post",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := revokeAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertEqual(t, resBody.PublicID, secretID)
				AssertEqual(t, resBody.Status, "revoked")
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEmpty(t, resBody.ClientSecret)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 200 OK on successful key revoke for private_key_jwt",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := revokeAccountCredentialBeforeEach(t, "private_key_jwt")
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertEqual(t, resBody.PublicID, secretID)
				AssertEqual(t, resBody.Status, "revoked")
				AssertEmpty(t, resBody.ClientSecretJWK)
				AssertEmpty(t, resBody.ClientSecret)
			},
			PathFn: pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent credential",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := revokeAccountCredentialBeforeEach(t, "client_secret_post")
				clientID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent secret",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := revokeAccountCredentialBeforeEach(t, "client_secret_basic")
				secretID = utils.Base62UUID()
				return nil, accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (any, string) {
				revokeAccountCredentialBeforeEach(t, "client_secret_post")
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
			PathFn:    pathFN,
		},
		{
			Name: "Should return 403 FORBIDDEN without account:credentials:write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead})

				cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CredentialsType: "service",
					Name:            "forbidden-revoke",
					Scopes:          []string{"account:admin"},
					AuthMethod:      "client_secret_basic",
					Transport:       "https",
					ClientURI:       "https://forbidden-revoke.example.com",
					SoftwareID:      "forbidden-revoke-service",
					SoftwareVersion: "1.0.0",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				secretID = cred.ClientSecretID
				return nil, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
			PathFn:    pathFN,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodDelete, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}
