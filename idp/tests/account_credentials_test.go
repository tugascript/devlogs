// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	rand2 "math/rand/v2"
	"net/http"
	"strings"
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
			t.Fatal("Failed to delete all accounts", err)
		}

		accountsCleanUp(t)
	}
}

func TestCreateAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	testCases := []TestRequestCase[bodies.CreateAccountCredentialsBody]{
		{
			Name: "Should return 201 CREATED with secret and both client secrets",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:admin"},
					Alias:       "admin",
					AuthMethods: "both_client_secrets",
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
				AssertEqual(t, len(resBody.AuthMethods), 2)
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodClientSecretBasic)
				AssertEqual(t, resBody.AuthMethods[1], database.AuthMethodClientSecretPost)
			},
		},
		{
			Name: "Should return 201 CREATED with secret and private key JWT",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:credentials:read", "account:credentials:write"},
					Alias:       "super-key",
					AuthMethods: "private_key_jwt",
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
				AssertEqual(t, len(resBody.AuthMethods), 1)
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodPrivateKeyJwt)
			},
		},
		{
			Name: "Should return 201 CREATED with secret and client secret post",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:apps:read", "account:apps:write"},
					Alias:       "app-keys",
					AuthMethods: "client_secret_post",
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
				AssertEqual(t, len(resBody.AuthMethods), 1)
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodClientSecretPost)
			},
		},
		{
			Name: "Should return 201 CREATED with secret and client secret basic",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:users:read", "account:users:write"},
					Alias:       "user-keys",
					AuthMethods: "client_secret_basic",
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
				AssertEqual(t, len(resBody.AuthMethods), 1)
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodClientSecretBasic)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST with bad values",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"invalid:scope", "account:users:readsd"},
					Alias:       "invalid asdfasd ### scope",
					AuthMethods: "client_secret_not_valid",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, len(resBody.Fields), 4)
				AssertEqual(t, resBody.Fields[0].Param, "scopes[0]")
				AssertEqual(t, resBody.Fields[1].Param, "scopes[1]")
				AssertEqual(t, resBody.Fields[2].Param, "alias")
				AssertEqual(t, resBody.Fields[3].Param, "auth_methods")
			},
		},
		{
			Name: "Should return 409 CONFLICT with existing alias",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)

				if _, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					Alias:           "existing-alias",
					Scopes:          []string{"account:users:read", "account:users:write"},
					AuthMethods:     "private_key_jwt",
				}); err != nil {
					t.Fatal("Failed to create initial account credentials", err)
				}

				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:admin"},
					Alias:       "existing-alias",
					AuthMethods: "client_secret_basic",
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.CreateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Account credentials alias already exists")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without access token",
			ReqFn: func(t *testing.T) (bodies.CreateAccountCredentialsBody, string) {
				return bodies.CreateAccountCredentialsBody{
					Scopes:      []string{"account:credentials:write", "account:auth_providers:read"},
					Alias:       "user-keys",
					AuthMethods: "client_secret_basic",
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
					Scopes:      []string{"account:apps:read", "account:apps:write"},
					Alias:       "app-keys",
					AuthMethods: "client_secret_post",
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

func TestListAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	listAccountBeforeEach := func(t *testing.T, n int) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		authMethodsList := []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
			"both_client_secrets",
		}
		scopesList := [][]string{
			{"account:admin"},
			{"account:credentials:read", "account:credentials:write"},
			{"account:apps:read", "account:apps:write"},
			{"account:users:read", "account:users:write"},
		}

		for i := 0; i < n; i++ {
			authMethods := authMethodsList[rand2.IntN(len(authMethodsList))]
			scopes := scopesList[rand2.IntN(len(scopesList))]
			alias := "cred-" + uuid.NewString()

			_, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
				RequestID:       uuid.NewString(),
				AccountPublicID: account.PublicID,
				AccountVersion:  account.Version(),
				Alias:           alias,
				Scopes:          scopes,
				AuthMethods:     authMethods,
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
				AssertEqual(
					t,
					strings.Split(resBody.Next, GetTestConfig(t).BackendDomain())[1],
					"/v1/accounts/credentials?offset=20&limit=20",
				)
				AssertEmpty(t, resBody.Previous)
			},
			Path: accountCredentialsPath,
		},
		{
			Name: "Should return 200 OK with paginated account credentials and previous link",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountBeforeEach(t, 12)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AccountCredentialsDTO]{})
				AssertEqual(t, len(resBody.Items), 2)
				AssertEqual(t, resBody.Total, 12)
				AssertEmpty(t, resBody.Next)
				AssertEqual(
					t,
					strings.Split(resBody.Previous, GetTestConfig(t).BackendDomain())[1],
					"/v1/accounts/credentials?offset=0&limit=20",
				)
			},
			Path: accountCredentialsPath + "?offset=10&limit=20",
		},
		{
			Name: "Should return 200 OK with paginated account with next and previous link",
			ReqFn: func(t *testing.T) (any, string) {
				accessToken := listAccountBeforeEach(t, 20)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AccountCredentialsDTO]{})
				backendDomain := GetTestConfig(t).BackendDomain()
				AssertEqual(t, len(resBody.Items), 5)
				AssertEqual(t, resBody.Total, 20)
				AssertEqual(
					t,
					strings.Split(resBody.Next, backendDomain)[1],
					"/v1/accounts/credentials?offset=15&limit=5",
				)
				AssertEqual(
					t,
					strings.Split(resBody.Previous, backendDomain)[1],
					"/v1/accounts/credentials?offset=5&limit=5",
				)
			},
			Path: accountCredentialsPath + "?offset=10&limit=5",
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

func TestGetAccountCredentials(t *testing.T) {
	const accountCredentialsPath = v1Path + paths.AccountsBase + paths.CredentialsBase

	var clientID string
	getAccountCredentialBeforeEach := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsRead, tokens.AccountScopeCredentialsWrite})

		cred, err := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			Alias:           "get-cred",
			Scopes:          []string{"account:admin"},
			AuthMethods:     "client_secret_basic",
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
				AssertNotEmpty(t, resBody.Alias)
				AssertEqual(t, len(resBody.AuthMethods), 1)
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodClientSecretBasic)
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
					Alias:           "forbidden-cred",
					Scopes:          []string{"account:admin"},
					AuthMethods:     "client_secret_basic",
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
			Alias:           "update-cred",
			Scopes:          []string{"account:admin"},
			AuthMethods:     "client_secret_basic",
		})
		if err != nil {
			t.Fatalf("Failed to create account credentials: %v", err)
		}
		clientID = cred.ClientID
		return accessToken
	}

	testCases := []TestRequestCase[bodies.UpdateAccountCredentialsBody]{
		{
			Name: "Should return 200 OK and update alias and scopes",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				accessToken := updateAccountCredentialBeforeEach(t)
				return bodies.UpdateAccountCredentialsBody{
					Alias:  "updated-alias",
					Scopes: []string{"account:users:read"},
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountCredentialsDTO{})
				AssertEqual(t, resBody.Alias, "updated-alias")
				AssertEqual(t, len(resBody.Scopes), 1)
				AssertEqual(t, resBody.Scopes[0], "account:users:read")
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
					Alias:  "invalid alias ###",
					Scopes: []string{"account:users:read", "invalid:scope"},
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, len(resBody.Fields), 2)
				AssertEqual(t, resBody.Fields[0].Param, "scopes[1]")
				AssertEqual(t, resBody.Fields[1].Param, "alias")
			},
			PathFn: func() string {
				return accountCredentialsPath + "/" + clientID
			},
		},
		{
			Name: "Should return 409 conflict and update alias and scopes",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountCredentialsBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderFacebook))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []string{tokens.AccountScopeCredentialsWrite})
				testS := GetTestServices(t)
				if _, err := testS.CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					Alias:           "existing-alias",
					Scopes:          []string{"account:users:read"},
					AuthMethods:     "client_secret_basic",
				}); err != nil {
					t.Fatalf("Failed to create initial account credentials: %v", err)
				}

				clientCreds, err := testS.CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					Alias:           "other-alias",
					Scopes:          []string{"account:users:read"},
					AuthMethods:     "client_secret_basic",
				})
				if err != nil {
					t.Fatalf("Failed to create initial account credentials: %v", err)
				}
				clientID = clientCreds.ClientID
				return bodies.UpdateAccountCredentialsBody{
					Alias:  "existing-alias",
					Scopes: []string{"account:users:read"},
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountCredentialsBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Account credentials alias already exists")
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
					Alias:  "new-alias",
					Scopes: []string{"account:users:read"},
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
					Alias:  "updated-alias",
					Scopes: []string{"account:users:read"},
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
					Alias:           "forbidden-cred",
					Scopes:          []string{"account:admin"},
					AuthMethods:     "client_secret_basic",
				})
				if err != nil {
					t.Fatalf("Failed to create account credentials: %v", err)
				}
				clientID = cred.ClientID
				return bodies.UpdateAccountCredentialsBody{
					Alias:  "updated-alias",
					Scopes: []string{"account:users:read"},
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
			Alias:           "delete-cred",
			Scopes:          []string{"account:admin"},
			AuthMethods:     "client_secret_basic",
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
					Alias:           "forbidden-cred",
					Scopes:          []string{"account:admin"},
					AuthMethods:     "client_secret_basic",
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
