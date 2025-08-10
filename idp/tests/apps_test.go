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

// createAppBody represents all possible fields for creating any app type
type createAppBody struct {
	// Base fields (required for all types)
	Type      string `json:"type"`
	Name      string `json:"name"`
	ClientURI string `json:"client_uri"`
	Domain    string `json:"domain,omitempty"`
	Transport string `json:"transport,omitempty"`

	// Common optional fields
	UsernameColumn string `json:"username_column,omitempty"`
	Algorithm      string `json:"algorithm,omitempty"`

	// Web/SPA/Native specific fields
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`

	// Device-specific fields
	AssociatedApps []string `json:"associated_apps,omitempty"`

	// Service-specific fields
	UsersAuthMethod string   `json:"users_auth_method,omitempty"`
	AllowedDomains  []string `json:"allowed_domains,omitempty"`
}

func TestCreateApp(t *testing.T) {
	testCases := []TestRequestCase[createAppBody]{
		{
			Name: "Should return 201 CREATED with web app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:                    "web",
					Name:                    "Test Web App",
					ClientURI:               "https://test-web-app.example.com",
					Domain:                  "other.example.com",
					UsernameColumn:          "email",
					Algorithm:               "ES256",
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://test-web-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, req.Domain, resBody.Domain)
				AssertEqual(t, database.AppTypeWeb, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with SPA app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:           "spa",
					Name:           "Test SPA App",
					ClientURI:      "https://test-spa-app.example.com",
					Domain:         "test-spa-app.example.com",
					UsernameColumn: "email",
					RedirectURIs:   []string{"https://test-spa-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeSpa, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with native app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:           "native",
					Name:           "Test Native App",
					ClientURI:      "https://test-native-app.example.com",
					UsernameColumn: "email",
					RedirectURIs:   []string{"com.testnativeapp://callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeNative, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with backend app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:                    "backend",
					Name:                    "Test Backend App",
					ClientURI:               "https://test-backend-app.example.com",
					UsernameColumn:          "email",
					TokenEndpointAuthMethod: "private_key_jwt",
					Algorithm:               "EdDSA",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeBackend, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
		},
		{
			Name: "Should return 201 CREATED with device app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
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
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeDevice, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
				AssertEmpty(t, resBody.ClientSecret)
			},
		},
		{
			Name: "Should return 201 CREATED with service app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:                    "service",
					Name:                    "Test Service App",
					ClientURI:               "https://test-service-app.example.com",
					Domain:                  "test-service-app.example.com",
					Transport:               "https",
					TokenEndpointAuthMethod: "private_key_jwt",
					Algorithm:               "ES256",
					UsersAuthMethod:         "client_secret_basic",
					AllowedDomains:          []string{},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeService, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
				AssertNotEmpty(t, resBody.ClientSecretJWK)
			},
		},
		{
			Name: "Should return 201 CREATED with a stdio MCP app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:                    "mcp",
					Name:                    "Test MCP App",
					ClientURI:               "https://test-mcp-app.example.com",
					Domain:                  "test-custom-app.example.com",
					Transport:               "stdio",
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://test-mcp-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeMcp, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertNotEmpty(t, resBody.ClientSecretID)
			},
		},
		{
			Name: "Should return 201 CREATED with a streamable_http MCP app data",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:                    "mcp",
					Name:                    "Test MCP App",
					ClientURI:               "https://test-mcp-app.example.com",
					Transport:               "streamable_http",
					TokenEndpointAuthMethod: "client_secret_basic",
					RedirectURIs:            []string{"https://test-mcp-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
				AssertEqual(t, database.AppTypeMcp, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
				AssertEmpty(t, resBody.ClientSecretID)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return createAppBody{
					Type:      "invalid",
					Name:      "TestApp",
					ClientURI: "https://test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ createAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				return createAppBody{
					Type:      "web",
					Name:      "Test App",
					ClientURI: "https://test-app.example.com",
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[createAppBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (createAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return createAppBody{
					Type:      "web",
					Name:      "Test App",
					ClientURI: "https://test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[createAppBody],
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CreationMethod:  database.CreationMethodDynamicRegistration,
					Name:            "Test Web App",
					UsernameColumn:  "email",
					AuthMethod:      "client_secret_post",
					Algorithm:       "ES256",
					ClientURI:       "https://test-web-app.example.com",
					Domain:          "test-web-app.example.com",
					Transport:       "https",
					RedirectURIs:    []string{"https://test-web-app.example.com/callback"},
				})
				if err != nil {
					t.Fatal("Failed to create test web app", err)
				}

				_, err = tServs.CreateSPANativeApp(context.Background(), services.CreateSPANativeAppOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppType:         database.AppTypeSpa,
					CreationMethod:  database.CreationMethodManual,
					Name:            "Test SPA App",
					UsernameColumn:  "email",
					ClientURI:       "https://test-spa-app.example.com",
					Domain:          "test-spa-app.example.com",
					Transport:       "https",
					RedirectURIs:    []string{"https://test-spa-app.example.com/callback"},
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CreationMethod:  database.CreationMethodDynamicRegistration,
					Name:            "Filtered Web App",
					UsernameColumn:  "email",
					AuthMethod:      "client_secret_post",
					Algorithm:       "ES256",
					ClientURI:       "https://filtered-web-app.example.com",
					Domain:          "filtered-web-app.example.com",
					Transport:       "https",
					RedirectURIs:    []string{"https://filtered-web-app.example.com/callback"},
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				// Create some test apps
				tServs := GetTestServices(t)
				_, err := tServs.CreateWebApp(context.Background(), services.CreateWebAppOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					CreationMethod:  database.CreationMethodManual,
					Name:            "Test Web App",
					UsernameColumn:  "email",
					AuthMethod:      "client_secret_post",
					Algorithm:       "ES256",
					ClientURI:       "https://test-web-app.example.com",
					Domain:          "test-web-app.example.com",
					Transport:       "https",
					RedirectURIs:    []string{"https://test-web-app.example.com/callback"},
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
				AssertEqual(t, database.AppTypeWeb, resBody.Items[0].AppType)
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
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
				AssertEqual(t, database.AppTypeWeb, resBody.AppType)
				AssertNotEmpty(t, resBody.ClientID)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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

func CreateTestWebApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateWebApp(ctx, services.CreateWebAppOptions{
		RequestID:             uuid.New().String(),
		AccountPublicID:       account.PublicID,
		CreationMethod:        database.CreationMethodManual,
		AccountVersion:        account.Version(),
		Name:                  "Test App",
		UsernameColumn:        "email",
		AuthMethod:            "client_secret_post",
		Algorithm:             "ES256",
		ClientURI:             "https://test-app.example.com",
		Domain:                "test-app.example.com",
		Transport:             "https",
		RedirectURIs:          []string{"https://test-app.example.com/callback"},
		AllowUserRegistration: true,
	})
	if err != nil {
		t.Fatal("Failed to create test app", err)
	}

	return appDTO
}

func CreateTestSPAApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateSPANativeApp(ctx, services.CreateSPANativeAppOptions{
		RequestID:       uuid.New().String(),
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		AppType:         database.AppTypeSpa,
		CreationMethod:  database.CreationMethodManual,
		Name:            "Test SPA App",
		UsernameColumn:  "email",
		ClientURI:       "https://test-spa-app.example.com",
		Domain:          "test-spa-app.example.com",
		Transport:       "https",
		RedirectURIs:    []string{"https://test-spa-app.example.com/callback"},
	})
	if err != nil {
		t.Fatal("Failed to create test SPA app", err)
	}

	return appDTO
}

func CreateTestNativeApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateSPANativeApp(ctx, services.CreateSPANativeAppOptions{
		RequestID:       uuid.New().String(),
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		AppType:         database.AppTypeNative,
		CreationMethod:  database.CreationMethodManual,
		Name:            "Test Native App",
		ClientURI:       "https://test-native-app.example.com",
		Domain:          "test-native-app.example.com",
		Transport:       "https",
		RedirectURIs:    []string{"com.testnativeapp://callback"},
	})
	if err != nil {
		t.Fatal("Failed to create test native app", err)
	}

	return appDTO
}

func CreateTestBackendApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateBackendApp(ctx, services.CreateBackendAppOptions{
		RequestID:       uuid.New().String(),
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		CreationMethod:  database.CreationMethodManual,
		Name:            "Test Backend App",
		UsernameColumn:  "email",
		AuthMethod:      "private_key_jwt",
		Algorithm:       "EdDSA",
		ClientURI:       "https://test-backend-app.example.com",
		Domain:          "test-backend-app.example.com",
	})
	if err != nil {
		t.Fatal("Failed to create test backend app", err)
	}

	return appDTO
}

func CreateTestDeviceApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateDeviceApp(ctx, services.CreateDeviceAppOptions{
		RequestID:       uuid.New().String(),
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		CreationMethod:  database.CreationMethodManual,
		Name:            "Test Device App",
		ClientURI:       "https://test-device-app.example.com",
		UsernameColumn:  "email",
		AssociatedApps:  []string{},
	})
	if err != nil {
		t.Fatal("Failed to create test device app", err)
	}

	return appDTO
}

func CreateTestServiceApp(t *testing.T, account *dtos.AccountDTO) dtos.AppDTO {
	tServs := GetTestServices(t)
	ctx := context.Background()

	appDTO, err := tServs.CreateServiceApp(ctx, services.CreateServiceAppOptions{
		RequestID:       uuid.New().String(),
		AccountPublicID: account.PublicID,
		AccountVersion:  account.Version(),
		CreationMethod:  database.CreationMethodManual,
		Name:            "Test Service App",
		AuthMethod:      "private_key_jwt",
		Algorithm:       "ES256",
		ClientURI:       "https://test-service-app.example.com",
		Domain:          "test-service-app.example.com",
		UsersAuthMethod: "client_secret_basic",
		AllowedDomains:  []string{"example.com"},
	})
	if err != nil {
		t.Fatal("Failed to create test service app", err)
	}

	return appDTO
}

type updateAppBody struct {
	Name            string `json:"name"`
	ClientURI       string `json:"client_uri"`
	LogoURI         string `json:"logo_uri,omitempty"`
	TOSURI          string `json:"tos_uri,omitempty"`
	PolicyURI       string `json:"policy_uri,omitempty"`
	SoftwareID      string `json:"software_id,omitempty"`
	SoftwareVersion string `json:"software_version,omitempty"`

	// Common optional fields
	UsernameColumn string `json:"username_column,omitempty"`

	// Native specific fields
	RedirectURIs []string `json:"redirect_uris,omitempty"`

	// Device specific fields
	AssociatedApps []string `json:"associated_apps,omitempty"`

	// Service specific fields
	UsersAuthMethod string   `json:"users_auth_method,omitempty"`
	AllowedDomains  []string `json:"allowed_domains,omitempty"`
}

func TestUpdateApp(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[updateAppBody]{
		{
			Name: "Should return 200 OK updating web app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:            "Updated Test App",
					ClientURI:       "https://updated-test-app.example.com",
					LogoURI:         "https://example.com/logo.png",
					TOSURI:          "https://example.com/tos",
					PolicyURI:       "https://example.com/policy",
					SoftwareID:      "test-app-v1",
					SoftwareVersion: "1.0.0",
					UsernameColumn:  "email",
					RedirectURIs:    []string{"https://updated-test-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
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
			Name: "Should return 200 OK updating SPA app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestSPAApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:           "Updated SPA App",
					ClientURI:      "https://updated-spa-app.example.com",
					UsernameColumn: "email",
					RedirectURIs:   []string{"https://updated-spa-app.example.com/callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
			},
		},
		{
			Name: "Should return 200 OK updating native app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestNativeApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:         "Updated Native App",
					ClientURI:    "https://updated-native-app.example.com",
					RedirectURIs: []string{"com.updatednativeapp://callback"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
			},
		},
		{
			Name: "Should return 200 OK updating backend app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestBackendApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:           "Updated Backend App",
					ClientURI:      "https://updated-backend-app.example.com",
					UsernameColumn: "email",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
			},
		},
		{
			Name: "Should return 200 OK updating device app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestDeviceApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:           "Updated Device App",
					ClientURI:      "https://updated-device-app.example.com",
					UsernameColumn: "email",
					AssociatedApps: []string{},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
			},
		},
		{
			Name: "Should return 200 OK updating service app data",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestServiceApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:           "Updated Service App",
					ClientURI:      "https://updated-service-app.example.com",
					AllowedDomains: []string{"example.com"},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDTO{})
				AssertEqual(t, req.Name, resBody.Name)
				AssertEqual(t, req.ClientURI, resBody.ClientURI)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[updateAppBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return updateAppBody{
					Name:      "",
					ClientURI: "invalid-url",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ updateAppBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				return updateAppBody{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[updateAppBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (updateAppBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return updateAppBody{
					Name:      "Updated Test App",
					ClientURI: "https://updated-test-app.example.com",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID()
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[updateAppBody],
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				getRes := PerformTestRequest(t, GetTestServer(t).App, 0, http.MethodGet, v1Path+paths.AppsBase+"/"+appClientID, "Bearer", accessToken, "application/json", nil)
				AssertTestStatusCode(t, getRes, http.StatusNotFound)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.CreateCredentialsSecretBody{}, accessToken
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.CreateCredentialsSecretBody{
					Algorithm: "EdDSA",
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				app := CreateTestWebApp(t, &account)
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
					Algorithm: "ES256",
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
