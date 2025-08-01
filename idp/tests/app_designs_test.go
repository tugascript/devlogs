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
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func appDesignsCleanUp(t *testing.T) func() {
	return func() {
		db := GetTestDatabase(t)

		if err := db.DeleteAllAppDesigns(context.Background()); err != nil {
			t.Fatal("Failed to delete all app designs", err)
		}
		if err := db.DeleteAllApps(context.Background()); err != nil {
			t.Fatal("Failed to delete all apps", err)
		}
		if err := db.DeleteAllAccounts(context.Background()); err != nil {
			t.Fatal("Failed to delete all accounts", err)
		}
	}
}

func TestCreateAppDesign(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[bodies.AppDesignBody]{
		{
			Name: "Should return 201 CREATED with app design data",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
					DarkColors: &bodies.ColorsOptions{
						PrimaryColor:    "FF6666",
						SecondaryColor:  "66FF66",
						BackgroundColor: "222222",
						TextColor:       "FFFFFF",
					},
					LogoURL:    "https://example.com/logo.png",
					FaviconURL: "https://example.com/favicon.ico",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req bodies.AppDesignBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDesignDTO{})
				AssertEqual(t, req.LightColors.PrimaryColor, resBody.LightColors.PrimaryColor)
				AssertEqual(t, req.LightColors.SecondaryColor, resBody.LightColors.SecondaryColor)
				AssertEqual(t, req.LightColors.BackgroundColor, resBody.LightColors.BackgroundColor)
				AssertEqual(t, req.LightColors.TextColor, resBody.LightColors.TextColor)
				AssertEqual(t, req.DarkColors.PrimaryColor, resBody.DarkColors.PrimaryColor)
				AssertEqual(t, req.DarkColors.SecondaryColor, resBody.DarkColors.SecondaryColor)
				AssertEqual(t, req.DarkColors.BackgroundColor, resBody.DarkColors.BackgroundColor)
				AssertEqual(t, req.DarkColors.TextColor, resBody.DarkColors.TextColor)
				AssertEqual(t, req.LogoURL, resBody.LogoURL)
				AssertEqual(t, req.FaviconURL, resBody.FaviconURL)
			},
		},
		{
			Name: "Should return 201 CREATED with only light colors",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, req bodies.AppDesignBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDesignDTO{})
				AssertEqual(t, req.LightColors.PrimaryColor, resBody.LightColors.PrimaryColor)
				AssertEqual(t, req.LightColors.SecondaryColor, resBody.LightColors.SecondaryColor)
				AssertEqual(t, req.LightColors.BackgroundColor, resBody.LightColors.BackgroundColor)
				AssertEqual(t, req.LightColors.TextColor, resBody.LightColors.TextColor)
				AssertEmpty(t, resBody.DarkColors)
				AssertEmpty(t, resBody.LogoURL)
				AssertEmpty(t, resBody.FaviconURL)
			},
		},
		{
			Name: "Should return 409 CONFLICT if app design already exists",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				// Create first app design
				tServs := GetTestServices(t)
				_, err := tServs.CreateAppDesign(context.Background(), services.AppDesignOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppClientID:     app.ClientID,
					LightColors: services.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				})
				if err != nil {
					t.Fatal("Failed to create first app design", err)
				}

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.AppDesignBody, res *http.Response) {
				assertErrorResponse(t, res, exceptions.StatusConflict, "App design already exists for this app")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "INVALID",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.AppDesignBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.AppDesignBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.AppDesignBody],
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.AppDesignBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPost, tc)
		})
	}

	t.Cleanup(appDesignsCleanUp(t))
}

func TestGetAppDesign(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with app design data",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				// Create app design first
				tServs := GetTestServices(t)
				_, err := tServs.CreateAppDesign(context.Background(), services.AppDesignOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppClientID:     app.ClientID,
					LightColors: services.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
					DarkColors: &services.ColorsOptions{
						PrimaryColor:    "FF6666",
						SecondaryColor:  "66FF66",
						BackgroundColor: "222222",
						TextColor:       "FFFFFF",
					},
					LogoURL:    "https://example.com/logo.png",
					FaviconURL: "https://example.com/favicon.ico",
				})
				if err != nil {
					t.Fatal("Failed to create app design", err)
				}

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDesignDTO{})
				AssertEqual(t, "FF0000", resBody.LightColors.PrimaryColor)
				AssertEqual(t, "00FF00", resBody.LightColors.SecondaryColor)
				AssertEqual(t, "FFFFFF", resBody.LightColors.BackgroundColor)
				AssertEqual(t, "000000", resBody.LightColors.TextColor)
				AssertEqual(t, "FF6666", resBody.DarkColors.PrimaryColor)
				AssertEqual(t, "66FF66", resBody.DarkColors.SecondaryColor)
				AssertEqual(t, "222222", resBody.DarkColors.BackgroundColor)
				AssertEqual(t, "FFFFFF", resBody.DarkColors.TextColor)
				AssertEqual(t, "https://example.com/logo.png", resBody.LogoURL)
				AssertEqual(t, "https://example.com/favicon.ico", resBody.FaviconURL)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app design does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
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
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(appDesignsCleanUp(t))
}

func TestUpdateAppDesign(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[bodies.AppDesignBody]{
		{
			Name: "Should return 200 OK updating app design data",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				// Create app design first
				tServs := GetTestServices(t)
				_, err := tServs.CreateAppDesign(context.Background(), services.AppDesignOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppClientID:     app.ClientID,
					LightColors: services.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				})
				if err != nil {
					t.Fatal("Failed to create app design", err)
				}

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
					DarkColors: &bodies.ColorsOptions{
						PrimaryColor:    "6666FF",
						SecondaryColor:  "FFFF66",
						BackgroundColor: "222222",
						TextColor:       "FFFFFF",
					},
					LogoURL:    "https://updated.com/logo.png",
					FaviconURL: "https://updated.com/favicon.ico",
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.AppDesignBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AppDesignDTO{})
				AssertEqual(t, req.LightColors.PrimaryColor, resBody.LightColors.PrimaryColor)
				AssertEqual(t, req.LightColors.SecondaryColor, resBody.LightColors.SecondaryColor)
				AssertEqual(t, req.LightColors.BackgroundColor, resBody.LightColors.BackgroundColor)
				AssertEqual(t, req.LightColors.TextColor, resBody.LightColors.TextColor)
				AssertEqual(t, req.DarkColors.PrimaryColor, resBody.DarkColors.PrimaryColor)
				AssertEqual(t, req.DarkColors.SecondaryColor, resBody.DarkColors.SecondaryColor)
				AssertEqual(t, req.DarkColors.BackgroundColor, resBody.DarkColors.BackgroundColor)
				AssertEqual(t, req.DarkColors.TextColor, resBody.DarkColors.TextColor)
				AssertEqual(t, req.LogoURL, resBody.LogoURL)
				AssertEqual(t, req.FaviconURL, resBody.FaviconURL)
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app design does not exist",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.AppDesignBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				// Create app design first
				tServs := GetTestServices(t)
				_, err := tServs.CreateAppDesign(context.Background(), services.AppDesignOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppClientID:     app.ClientID,
					LightColors: services.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				})
				if err != nil {
					t.Fatal("Failed to create app design", err)
				}

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "INVALID",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.AppDesignBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, ""
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.AppDesignBody],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.AppDesignBody],
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (bodies.AppDesignBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return bodies.AppDesignBody{
					LightColors: bodies.ColorsOptions{
						PrimaryColor:    "0000FF",
						SecondaryColor:  "FFFF00",
						BackgroundColor: "000000",
						TextColor:       "FFFFFF",
					},
				}, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[bodies.AppDesignBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodPut, tc)
		})
	}

	t.Cleanup(appDesignsCleanUp(t))
}

func TestDeleteAppDesign(t *testing.T) {
	var appClientID string
	setAppClientID := func(app dtos.AppDTO) {
		appClientID = app.ClientID
	}

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 204 NO CONTENT when deleting app design",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				app := CreateTestWebApp(t, &account)
				setAppClientID(app)
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				// Create app design first
				tServs := GetTestServices(t)
				_, err := tServs.CreateAppDesign(context.Background(), services.AppDesignOptions{
					RequestID:       uuid.New().String(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					AppClientID:     app.ClientID,
					LightColors: services.ColorsOptions{
						PrimaryColor:    "FF0000",
						SecondaryColor:  "00FF00",
						BackgroundColor: "FFFFFF",
						TextColor:       "000000",
					},
				})
				if err != nil {
					t.Fatal("Failed to create app design", err)
				}

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNoContent,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
			},
		},
		{
			Name: "Should return 404 NOT FOUND if app design does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
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
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
		{
			Name: "Should return 403 FORBIDDEN if no apps write scope",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				setAppClientID(CreateTestWebApp(t, &account))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsRead})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + appClientID + paths.AppDesignsBase
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[any],
		},
		{
			Name: "Should return 404 NOT FOUND if app does not exist",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken := GenerateScopedAccountAccessToken(t, &account, []tokens.AccountScope{tokens.AccountScopeAppsWrite})

				return nil, accessToken
			},
			PathFn: func() string {
				return v1Path + paths.AppsBase + "/" + utils.Base62UUID() + paths.AppDesignsBase
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodDelete, tc)
		})
	}

	t.Cleanup(appDesignsCleanUp(t))
}
