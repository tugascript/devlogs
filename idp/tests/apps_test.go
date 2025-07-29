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

func appsCleanUp(t *testing.T) func() {
	return func() {
		db := GetTestDatabase(t)

		if err := db.DeleteAllAppDesigns(context.Background()); err != nil {
			t.Fatal("Failed to delete all app designs", err)
		}
		if err := db.DeleteAllCredentialsSecrets(context.Background()); err != nil {
			t.Fatal("Failed to delete all credentials secrets", err)
		}
		if err := db.DeleteAllCredentialsKeys(context.Background()); err != nil {
			t.Fatal("Failed to delete all credentials keys", err)
		}
		if err := db.DeleteAllApps(context.Background()); err != nil {
			t.Fatal("Failed to delete all apps", err)
		}
		if err := db.DeleteAllAccounts(context.Background()); err != nil {
			t.Fatal("Failed to delete all accounts", err)
		}
	}
}

// CreateAppBody represents all possible fields for creating any app type
type CreateAppBody struct {
	// Base fields (required for all types)
	Type      string `json:"type"`
	Name      string `json:"name"`
	ClientURI string `json:"client_uri"`

	// Common optional fields
	UsernameColumn string `json:"username_column,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`

	// Web/SPA specific fields
	AuthMethods         string   `json:"auth_methods,omitempty"`
	CallbackURLs        []string `json:"callback_urls,omitempty"`
	LogoutURLs          []string `json:"logout_urls,omitempty"`
	AllowedOrigins      []string `json:"allowed_origins,omitempty"`
	CodeChallengeMethod string   `json:"code_challenge_method,omitempty"`

	// Native specific fields
	CallbackURIs []string `json:"callback_uris,omitempty"`
	LogoutURIs   []string `json:"logout_uris,omitempty"`

	// Backend specific fields
	Issuers          []string `json:"issuers,omitempty"`
	ConfirmationURL  string   `json:"confirmation_url,omitempty"`
	ResetPasswordURL string   `json:"reset_password_url,omitempty"`

	// Device specific fields
	AssociatedApps []string `json:"associated_apps,omitempty"`

	// Service specific fields
	UsersAuthMethods string   `json:"users_auth_methods,omitempty"`
	AllowedDomains   []string `json:"allowed_domains,omitempty"`
}

func TestCreateApp(t *testing.T) {
	testCases := []TestRequestCase[CreateAppBody]{
		{
			Name: "Should return 201 CREATED with web app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:                "web",
					Name:                "Test Web App",
					ClientURI:           "https://test-web-app.example.com",
					UsernameColumn:      "email",
					Algorithm:           "ES256",
					AuthMethods:         "client_secret_basic",
					CallbackURLs:        []string{"https://test-web-app.example.com/callback"},
					LogoutURLs:          []string{"https://test-web-app.example.com/logout"},
					AllowedOrigins:      []string{"https://test-web-app.example.com"},
					CodeChallengeMethod: "S256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeWeb, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with SPA app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:                "spa",
					Name:                "Test SPA App",
					ClientURI:           "https://test-spa-app.example.com",
					UsernameColumn:      "email",
					CallbackURLs:        []string{"https://test-spa-app.example.com/callback"},
					LogoutURLs:          []string{"https://test-spa-app.example.com/logout"},
					AllowedOrigins:      []string{"https://test-spa-app.example.com"},
					CodeChallengeMethod: "S256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeSpa, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with native app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:                "native",
					Name:                "Test Native App",
					ClientURI:           "https://test-native-app.example.com",
					UsernameColumn:      "email",
					CallbackURIs:        []string{"com.testnativeapp://callback"},
					LogoutURIs:          []string{"com.testnativeapp://logout"},
					CodeChallengeMethod: "S256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeNative, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with backend app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:             "backend",
					Name:             "Test Backend App",
					ClientURI:        "https://test-backend-app.example.com",
					UsernameColumn:   "email",
					Algorithm:        "ES256",
					Issuers:          []string{"https://test-backend-app.example.com"},
					ConfirmationURL:  "https://test-backend-app.example.com/confirm",
					ResetPasswordURL: "https://test-backend-app.example.com/reset",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeBackend, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
		},
		{
			Name: "Should return 201 CREATED with device app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:           "device",
					Name:           "Test Device App",
					ClientURI:      "https://test-device-app.example.com",
					UsernameColumn: "email",
					AssociatedApps: []string{},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeDevice, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with service app data",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:             "service",
					Name:             "Test Service App",
					ClientURI:        "https://test-service-app.example.com",
					Algorithm:        "ES256",
					Issuers:          []string{"https://test-service-app.example.com"},
					UsersAuthMethods: "client_secret_basic",
					AllowedDomains:   []string{},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeService, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return CreateAppBody{
					Type:      "invalid",
					Name:      "TestApp",
					ClientURI: "https://test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ CreateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				return CreateAppBody{
					Type:      "web",
					Name:      "Test App",
					ClientURI: "https://test-app.example.com",
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[CreateAppBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (CreateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return CreateAppBody{
					Type:      "web",
					Name:      "Test App",
					ClientURI: "https://test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[CreateAppBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPost, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestListApps(t *testing.T) {
	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with apps list",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:           uuid.New().String(),
					AccountPublicID:     account.PublicID,
					AccountVersion:      account.Version(),
					Name:                "Test Web App",
					UsernameColumn:      "email",
					AuthMethods:         "both_client_secrets",
					Algorithm:           "HS256",
					ClientURI:           "https://test-web-app.example.com",
					CallbackURIs:        []string{"https://test-web-app.example.com/callback"},
					LogoutURIs:          []string{"https://test-web-app.example.com/logout"},
					AllowedOrigins:      []string{"https://test-web-app.example.com"},
					CodeChallengeMethod: "S256",
				})
				if err != nil {
					t.Fatal("Failed to create test web app", err)
				}

				_, err = tServs.CreateSPAApp(context.Background(), services.CreateSPAAppOptions{
					RequestID:           uuid.New().String(),
					AccountPublicID:     account.PublicID,
					AccountVersion:      account.Version(),
					Name:                "Test SPA App",
					UsernameColumn:      "email",
					ClientURI:           "https://test-spa-app.example.com",
					CallbackURIs:        []string{"https://test-spa-app.example.com/callback"},
					LogoutURIs:          []string{"https://test-spa-app.example.com/logout"},
					AllowedOrigins:      []string{"https://test-spa-app.example.com"},
					CodeChallengeMethod: "S256",
				})
				if err != nil {
					t.Fatal("Failed to create test SPA app", err)
				}

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AppDTO]{})
				AssertEqual(t, int64(2), resBody.Total)
				AssertEqual(t, 2, len(resBody.Items))
			},
		},
		{
			Name: "Should return 200 OK with filtered apps by name",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:           uuid.New().String(),
					AccountPublicID:     account.PublicID,
					AccountVersion:      account.Version(),
					Name:                "Filtered Web App",
					UsernameColumn:      "email",
					AuthMethods:         "both_client_secrets",
					Algorithm:           "HS256",
					ClientURI:           "https://filtered-web-app.example.com",
					CallbackURIs:        []string{"https://filtered-web-app.example.com/callback"},
					LogoutURIs:          []string{"https://filtered-web-app.example.com/logout"},
					AllowedOrigins:      []string{"https://filtered-web-app.example.com"},
					CodeChallengeMethod: "S256",
				})
				if err != nil {
					t.Fatal("Failed to create test web app", err)
				}

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "?name=Filtered"
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AppDTO]{})
				AssertEqual(t, int64(1), resBody.Total)
				AssertEqual(t, 1, len(resBody.Items))
				AssertStringContains(t, resBody.Items[0].Name, "Filtered")
			},
		},
		{
			Name: "Should return 200 OK with filtered apps by type",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:           uuid.New().String(),
					AccountPublicID:     account.PublicID,
					AccountVersion:      account.Version(),
					Name:                "Test Web App",
					UsernameColumn:      "email",
					AuthMethods:         "both_client_secrets",
					Algorithm:           "HS256",
					ClientURI:           "https://test-web-app.example.com",
					CallbackURIs:        []string{"https://test-web-app.example.com/callback"},
					LogoutURIs:          []string{"https://test-web-app.example.com/logout"},
					AllowedOrigins:      []string{"https://test-web-app.example.com"},
					CodeChallengeMethod: "S256",
				})
				if err != nil {
					t.Fatal("Failed to create test web app", err)
				}

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "?type=web"
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.AppDTO]{})
				AssertEqual(t, int64(1), resBody.Total)
				AssertEqual(t, 1, len(resBody.Items))
				AssertEqual(t, database.AppTypeWeb, resBody.Items[0].Type)
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestGetAppWithRelatedConfigs(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with app and related configs",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, "Test App", resBody.Name)
				AssertEqual(t, "https://test-app.example.com", resBody.ClientURI)
				AssertEqual(t, database.AppTypeWeb, resBody.Type)
				AssertNotEmpty(t, resBody.ClientID)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestUpdateApp(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[bodies.UpdateAppBodyBase]{
		{
			Name: "Should return 200 OK updating app data",
			ReqFn: func(t *testing.T) (bodies.UpdateAppBodyBase, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.UpdateAppBodyBase{
					Name:            "Updated Test App",
					ClientURI:       "https://updated-test-app.example.com",
					LogoURI:         "https://example.com/logo.png",
					TOSURI:          "https://example.com/tos",
					PolicyURI:       "https://example.com/policy",
					SoftwareID:      "test-app-v1",
					SoftwareVersion: "1.0.0",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateAppBodyBase, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, req.LogoURI, resBody.LogoURI)
				AssertEqual(t, req.TOSURI, resBody.TosURI)
				AssertEqual(t, req.PolicyURI, resBody.PolicyURI)
				AssertEqual(t, req.SoftwareID, resBody.SoftwareID)
				AssertEqual(t, req.SoftwareVersion, resBody.SoftwareVersion)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (bodies.UpdateAppBodyBase, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.UpdateAppBodyBase{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.UpdateAppBodyBase],
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.UpdateAppBodyBase, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.UpdateAppBodyBase{
					Name:      "",
					ClientURI: "invalid-url",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAppBodyBase, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.UpdateAppBodyBase, string) {
				return bodies.UpdateAppBodyBase{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.UpdateAppBodyBase],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (bodies.UpdateAppBodyBase, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return bodies.UpdateAppBodyBase{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.UpdateAppBodyBase],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPut, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestDeleteApp(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 204 NO CONTENT when deleting app",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusNoContent,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				// Verify app was deleted by trying to get it
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				getRes := PerformTestRequest(t, GetTestServer(t).App, 0, http.MethodGet, v1Path+paths.AppsBase+"/"+appClientID, "Bearer", accessToken, "application/json", nil)
				AssertTestStatusCode(t, getRes, http.StatusNotFound)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodDelete, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestListAppSecrets(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with app secrets list",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + "/secrets"
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.PaginationDTO[dtos.ClientCredentialsSecretDTO]{})
				AssertEqual(t, int64(1), resBody.Total) // Default secret created with app
				AssertEqual(t, 1, len(resBody.Items))
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps read scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}

func TestCreateAppSecret(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[bodies.CreateCredentialsSecretBody]{
		{
			Name: "Should return 201 CREATED with new app secret",
			ReqFn: func(t *testing.T) (bodies.CreateCredentialsSecretBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.CreateCredentialsSecretBody{
					Algorithm: "HS256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + "/secrets"
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.CreateCredentialsSecretBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ClientCredentialsSecretDTO{})
				AssertNotEmpty(t, resBody.PublicID)
				AssertNotEmpty(t, resBody.ClientSecret)
				AssertNotEmpty(t, resBody.ClientSecretExp)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (bodies.CreateCredentialsSecretBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.CreateCredentialsSecretBody{
					Algorithm: "HS256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.CreateCredentialsSecretBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.CreateCredentialsSecretBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.CreateCredentialsSecretBody{
					Algorithm: "INVALID",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + "/secrets"
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.CreateCredentialsSecretBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.CreateCredentialsSecretBody, string) {
				return bodies.CreateCredentialsSecretBody{
					Algorithm: "HS256",
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.CreateCredentialsSecretBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (bodies.CreateCredentialsSecretBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return bodies.CreateCredentialsSecretBody{
					Algorithm: "HS256",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + "/secrets"
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.CreateCredentialsSecretBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPost, tc)
		})
	}

	t.Cleanup(appsCleanUp(t))
}
