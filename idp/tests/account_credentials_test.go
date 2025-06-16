// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"net/http"
	"testing"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
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
				AssertEqual(t, resBody.AuthMethods[0], database.AuthMethodClientSecretBasic)
				AssertEqual(t, resBody.AuthMethods[1], database.AuthMethodClientSecretPost)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, accountCredentialsPath, tc)
		})
	}

	t.Cleanup(accountCredentialsCleanUp(t))
}
