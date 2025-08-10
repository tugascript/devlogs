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
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
)

func TestGetCurrentAccount(t *testing.T) {
	const getCurrentAccountPath = v1Path + paths.AccountsBase + paths.AccountUserInfo

	testCases := []TestRequestCase[any]{
		{
			Name: "Should return 200 OK with account data",
			ReqFn: func(t *testing.T) (any, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return nil, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ any, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountDTO{})
				AssertNotEmpty(t, resBody.PublicID)
				AssertNotEmpty(t, resBody.Email)
				AssertNotEmpty(t, resBody.GivenName)
				AssertNotEmpty(t, resBody.FamilyName)
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (any, string) {
				return nil, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[any],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, getCurrentAccountPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestUpdateAccount(t *testing.T) {
	const updateAccountPath = v1Path + paths.AccountsBase + paths.AccountUserInfo

	testCases := []TestRequestCase[bodies.UpdateAccountBody]{
		{
			Name: "Should return 200 OK updating account data",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountBody{
					GivenName:  "Updated",
					FamilyName: "User",
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AccountDTO{})
				AssertEqual(t, req.GivenName, resBody.GivenName)
				AssertEqual(t, req.FamilyName, resBody.FamilyName)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountBody{
					GivenName:  "",
					FamilyName: "",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 2, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountBody, string) {
				return bodies.UpdateAccountBody{
					GivenName:  "Updated",
					FamilyName: "User",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.UpdateAccountBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPut, updateAccountPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestUpdateAccountPassword(t *testing.T) {
	const updatePasswordPath = v1Path + paths.AccountsBase + paths.AccountPassword

	testCases := []TestRequestCase[bodies.UpdatePasswordBody]{
		{
			Name: "Should return 200 OK updating password",
			ReqFn: func(t *testing.T) (bodies.UpdatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "NewPassword123!"
				return bodies.UpdatePasswordBody{
					OldPassword: data.Password,
					Password:    newPassword,
					Password2:   newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.UpdatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK pending password update confirmation",
			ReqFn: func(t *testing.T) (bodies.UpdatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
					RequestID:     requestID,
					PublicID:      account.PublicID,
					Version:       account.Version(),
					TwoFactorType: services.TwoFactorEmail,
					Password:      data.Password,
				}); err != nil {
					t.Fatalf("failed to enable 2FA for account: %v", err)
				}

				account, serviceErr := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
					RequestID: requestID,
					PublicID:  account.PublicID,
				})
				if serviceErr != nil {
					t.Fatalf("failed to get account by public ID: %v", serviceErr)
				}

				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "NewPassword123!"
				return bodies.UpdatePasswordBody{
					OldPassword: data.Password,
					Password:    newPassword,
					Password2:   newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.UpdatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 403 FORBIDDEN if trying to update password of an account without password",
			ReqFn: func(t *testing.T) (bodies.UpdatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderApple)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "NewPassword123!"
				return bodies.UpdatePasswordBody{
					OldPassword: newPassword,
					Password:    newPassword,
					Password2:   newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.UpdatePasswordBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.UpdatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "weak"
				return bodies.UpdatePasswordBody{
					OldPassword: data.Password,
					Password:    newPassword,
					Password2:   newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if old password is wrong",
			ReqFn: func(t *testing.T) (bodies.UpdatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "NewPassword123!"
				return bodies.UpdatePasswordBody{
					OldPassword: "WrongPassword123!",
					Password:    newPassword,
					Password2:   newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Invalid password")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPatch, updatePasswordPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestConfirmUpdateAccountPassword(t *testing.T) {
	const confirmPasswordPath = v1Path + paths.AccountsBase + paths.AccountPassword + paths.Confirm

	genTwoFactorAccount := func(t *testing.T, twoFactorType string) (dtos.AccountDTO, string) {
		data := GenerateFakeAccountData(t, services.AuthProviderLocal)
		account := CreateTestAccount(t, data)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
			RequestID:     requestID,
			PublicID:      account.PublicID,
			Version:       account.Version(),
			TwoFactorType: twoFactorType,
			Password:      data.Password,
		}); err != nil {
			t.Fatal("Failed to enable 2FA", err)
		}

		account, serviceErr := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
			RequestID: requestID,
			PublicID:  account.PublicID,
		})
		if serviceErr != nil {
			t.Fatalf("failed to get account by public ID: %v", serviceErr)
		}

		return account, data.Password
	}

	testCases := []TestRequestCase[bodies.TwoFactorLoginBody]{
		{
			Name: "Should return 200 OK and update password after confirmation for TOTP 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password := genTwoFactorAccount(t, services.TwoFactorTotp)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountPassword(
					context.Background(),
					services.UpdateAccountPasswordOptions{
						RequestID:   requestID,
						PublicID:    account.PublicID,
						Version:     account.Version(),
						Password:    password,
						NewPassword: "NewPassword123!",
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account password: %v", serviceErr)
				}

				accountTOTP, err := GetTestDatabase(t).FindAccountTotpByAccountID(context.Background(), account.ID())
				if err != nil {
					t.Fatal("Failed to find account TOTP", err)
				}

				secret, serviceErr := GetTestCrypto(t).DecryptWithDEK(context.Background(), crypto.DecryptWithDEKOptions{
					RequestID: requestID,
					GetDecryptDEKfn: GetTestServices(t).BuildGetDecAccountDEKFn(
						context.Background(),
						services.BuildGetDecAccountDEKFnOptions{
							RequestID: requestID,
							AccountID: account.ID(),
						},
					),
					Ciphertext: accountTOTP.Secret,
				})
				if serviceErr != nil {
					t.Fatal("Failed to decrypt account TOTP", serviceErr)
				}

				code, err := totp.GenerateCode(secret, time.Now().UTC())
				if err != nil {
					t.Fatal("Failed to generate code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK and update password after confirmation for email 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountPassword(
					context.Background(),
					services.UpdateAccountPasswordOptions{
						RequestID:   requestID,
						PublicID:    account.PublicID,
						Version:     account.Version(),
						Password:    password,
						NewPassword: "NewPassword123!",
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account password: %v", serviceErr)
				}

				code, err := GetTestCache(t).AddTwoFactorCode(context.Background(), cache.AddTwoFactorCodeOptions{
					RequestID: uuid.NewString(),
					AccountID: account.ID(),
					TTL:       GetTestTokens(t).Get2FATTL(),
				})
				if err != nil {
					t.Fatal("Failed to create email code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if code is malformed",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountPassword(
					context.Background(),
					services.UpdateAccountPasswordOptions{
						RequestID:   requestID,
						PublicID:    account.PublicID,
						Version:     account.Version(),
						Password:    password,
						NewPassword: "NewPassword123!",
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account password: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "not-a-valid-code",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "code", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if code is invalid",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountPassword(
					context.Background(),
					services.UpdateAccountPasswordOptions{
						RequestID:   requestID,
						PublicID:    account.PublicID,
						Version:     account.Version(),
						Password:    password,
						NewPassword: "NewPassword123!",
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account password: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "129876",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				return bodies.TwoFactorLoginBody{
					Code: "123456",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, confirmPasswordPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestCreateAccountPassword(t *testing.T) {
	const createPasswordPath = v1Path + paths.AccountsBase + paths.AccountPassword

	testCases := []TestRequestCase[bodies.CreatePasswordBody]{
		{
			Name: "Should return 200 OK creating password for account without password",
			ReqFn: func(t *testing.T) (bodies.CreatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderApple)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "NewPassword123!"
				return bodies.CreatePasswordBody{
					Password:  newPassword,
					Password2: newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.CreatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.CreatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderApple)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.CreatePasswordBody{
					Password:  "short",
					Password2: "short",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.CreatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 409 CONFLICT if account already has a password",
			ReqFn: func(t *testing.T) (bodies.CreatePasswordBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				newPassword := "AnotherPassword123!"
				return bodies.CreatePasswordBody{
					Password:  newPassword,
					Password2: newPassword,
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.CreatePasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Password already set for account")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.CreatePasswordBody, string) {
				return bodies.CreatePasswordBody{
					Password:  "NewPassword123!",
					Password2: "NewPassword123!",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.CreatePasswordBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, createPasswordPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestUpdateAccountEmail(t *testing.T) {
	const updateEmailPath = v1Path + paths.AccountsBase + paths.AccountEmail

	testCases := []TestRequestCase[bodies.UpdateEmailBody]{
		{
			Name: "Should return 200 OK updating account email",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateEmailBody{
					Email:    "updated.email@example.com",
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK pending email update confirmation",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
					RequestID:     requestID,
					PublicID:      account.PublicID,
					Version:       account.Version(),
					TwoFactorType: services.TwoFactorEmail,
					Password:      accountData.Password,
				}); err != nil {
					t.Fatalf("failed to enable 2FA for account: %v", err)
				}

				account, serviceErr := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
					RequestID: requestID,
					PublicID:  account.PublicID,
				})
				if serviceErr != nil {
					t.Fatalf("failed to get account by public ID: %v", serviceErr)
				}

				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateEmailBody{
					Email:    requestID + ".updated.email@example.com",
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if email is the same as current",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateEmailBody{
					Email:    accountData.Email,
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, resBody.Message, "New email must be different from current")
			},
		},
		{
			Name: "Should return 409 CONFLICT if email is already in use",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)

				// Create another account with the same email
				anotherAccountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				CreateTestAccount(t, anotherAccountData)

				return bodies.UpdateEmailBody{
					Email:    anotherAccountData.Email,
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Email already in use")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateEmailBody{
					Email:    "not-an-email",
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "email", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if password is wrong",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateEmailBody{
					Email:    "updated.email@example.com",
					Password: "WrongPassword123!",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateEmailBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Invalid password")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.UpdateEmailBody, string) {
				return bodies.UpdateEmailBody{
					Email:    "updated.email@example.com",
					Password: "Password123!",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.UpdateEmailBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPatch, updateEmailPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestConfirmUpdateAccountEmail(t *testing.T) {
	const confirmEmailPath = v1Path + paths.AccountsBase + paths.AccountEmail + paths.Confirm

	genTwoFactorAccount := func(t *testing.T, twoFactorType string) (dtos.AccountDTO, string, string) {
		accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
		account := CreateTestAccount(t, accountData)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
			RequestID:     requestID,
			PublicID:      account.PublicID,
			Version:       account.Version(),
			TwoFactorType: twoFactorType,
			Password:      accountData.Password,
		}); err != nil {
			t.Fatalf("failed to enable 2FA for account: %v", err)
		}

		account, serviceErr := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
			RequestID: requestID,
			PublicID:  account.PublicID,
		})
		if serviceErr != nil {
			t.Fatalf("failed to get account by public ID: %v", serviceErr)
		}

		return account, accountData.Password, requestID + ".updated.email@example.com"
	}

	testCases := []TestRequestCase[bodies.TwoFactorLoginBody]{
		{
			Name: "Should return 200 OK and update password after confirmation for TOTP 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newEmail := genTwoFactorAccount(t, services.TwoFactorTotp)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountEmail(
					context.Background(),
					services.UpdateAccountEmailOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Email:     newEmail,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account email: %v", serviceErr)
				}

				accountTOTP, err := GetTestDatabase(t).FindAccountTotpByAccountID(context.Background(), account.ID())
				if err != nil {
					t.Fatal("Failed to find account TOTP", err)
				}

				secret, serviceErr := GetTestCrypto(t).DecryptWithDEK(context.Background(), crypto.DecryptWithDEKOptions{
					RequestID: requestID,
					GetDecryptDEKfn: GetTestServices(t).BuildGetGlobalDecDEKFn(
						context.Background(),
						requestID,
					),
					Ciphertext: accountTOTP.Secret,
				})
				if serviceErr != nil {
					t.Fatal("Failed to decrypt account DEK", serviceErr)
				}

				code, err := totp.GenerateCode(secret, time.Now().UTC())
				if err != nil {
					t.Fatal("Failed to generate code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK and update email after confirmation for email 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newEmail := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountEmail(
					context.Background(),
					services.UpdateAccountEmailOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Email:     newEmail,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account email: %v", serviceErr)
				}

				code, err := GetTestCache(t).AddTwoFactorCode(context.Background(), cache.AddTwoFactorCodeOptions{
					RequestID: requestID,
					AccountID: account.ID(),
					TTL:       GetTestTokens(t).Get2FATTL(),
				})
				if err != nil {
					t.Fatal("Failed to create email code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if code is malformed",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newEmail := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountEmail(
					context.Background(),
					services.UpdateAccountEmailOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Email:     newEmail,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account email: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "not-a-valid-code",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "code", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if code is invalid",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newEmail := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountEmail(
					context.Background(),
					services.UpdateAccountEmailOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Email:     newEmail,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account email: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "129876",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				return bodies.TwoFactorLoginBody{
					Code: "123456",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, confirmEmailPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestUpdateAccountUsername(t *testing.T) {
	const updateUsernamePath = v1Path + paths.AccountsBase + paths.AccountUsername

	testCases := []TestRequestCase[bodies.UpdateAccountUsernameBody]{
		{
			Name: "Should return 200 OK updating account username",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: "newusername-" + uuid.NewString()[:8],
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK updating account username even without password for social accounts",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderFacebook)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: "newusername-" + uuid.NewString()[:8],
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK pending username update confirmation if 2FA enabled",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				testS := GetTestServices(t)
				requestID := uuid.NewString()
				if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
					RequestID:     requestID,
					PublicID:      account.PublicID,
					Version:       account.Version(),
					TwoFactorType: services.TwoFactorEmail,
					Password:      accountData.Password,
				}); err != nil {
					t.Fatalf("failed to enable 2FA for account: %v", err)
				}
				account, err := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
					RequestID: requestID,
					PublicID:  account.PublicID,
				})
				if err != nil {
					t.Fatalf("failed to get account by public ID: %v", err)
				}
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: "pendingusername-" + uuid.NewString()[:8],
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if username is the same as current",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: account.Username,
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, resBody.Message, "New username must be different from current")
			},
		},
		{
			Name: "Should return 409 CONFLICT if username is already in use",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				anotherAccountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				anotherAccount := CreateTestAccount(t, anotherAccountData)
				return bodies.UpdateAccountUsernameBody{
					Username: anotherAccount.Username,
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Username already in use")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if validation fails",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: "x",
					Password: accountData.Password,
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "username", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if password is wrong",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, accountData)
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.UpdateAccountUsernameBody{
					Username: "newusername-" + uuid.NewString()[:8],
					Password: "WrongPassword123!",
				}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.UpdateAccountUsernameBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, resBody.Message, "Invalid password")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.UpdateAccountUsernameBody, string) {
				return bodies.UpdateAccountUsernameBody{
					Username: "newusername_" + uuid.NewString()[:8],
					Password: "Password123!",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.UpdateAccountUsernameBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPatch, updateUsernamePath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestConfirmUpdateAccountUsername(t *testing.T) {
	const confirmUsernamePath = v1Path + paths.AccountsBase + paths.AccountUsername + paths.Confirm

	genTwoFactorAccount := func(t *testing.T, twoFactorType string) (dtos.AccountDTO, string, string) {
		accountData := GenerateFakeAccountData(t, services.AuthProviderLocal)
		account := CreateTestAccount(t, accountData)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
			RequestID:     requestID,
			PublicID:      account.PublicID,
			Version:       account.Version(),
			TwoFactorType: twoFactorType,
			Password:      accountData.Password,
		}); err != nil {
			t.Fatalf("failed to enable 2FA for account: %v", err)
		}

		account, serviceErr := testS.GetAccountByPublicID(context.Background(), services.GetAccountByPublicIDOptions{
			RequestID: requestID,
			PublicID:  account.PublicID,
		})
		if serviceErr != nil {
			t.Fatalf("failed to get account by public ID: %v", serviceErr)
		}

		return account, accountData.Password, "newusername-" + uuid.NewString()[:8]
	}

	testCases := []TestRequestCase[bodies.TwoFactorLoginBody]{
		{
			Name: "Should return 200 OK and update username after confirmation for TOTP 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newUsername := genTwoFactorAccount(t, services.TwoFactorTotp)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountUsername(
					context.Background(),
					services.UpdateAccountUsernameOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Username:  newUsername,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account username: %v", serviceErr)
				}

				accountTOTP, err := GetTestDatabase(t).FindAccountTotpByAccountID(context.Background(), account.ID())
				if err != nil {
					t.Fatal("Failed to find account TOTP", err)
				}

				secret, serviceErr := GetTestCrypto(t).DecryptWithDEK(context.Background(), crypto.DecryptWithDEKOptions{
					RequestID: requestID,
					GetDecryptDEKfn: GetTestServices(t).BuildGetGlobalDecDEKFn(
						context.Background(),
						requestID,
					),
					Ciphertext: accountTOTP.Secret,
				})
				if serviceErr != nil {
					t.Fatal("Failed to decrypt account DEK", serviceErr)
				}

				code, err := totp.GenerateCode(secret, time.Now().UTC())
				if err != nil {
					t.Fatal("Failed to generate code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 200 OK and update username after confirmation for email 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newUsername := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountUsername(
					context.Background(),
					services.UpdateAccountUsernameOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Username:  newUsername,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account username: %v", serviceErr)
				}

				code, err := GetTestCache(t).AddTwoFactorCode(context.Background(), cache.AddTwoFactorCodeOptions{
					RequestID: uuid.NewString(),
					AccountID: account.ID(),
					TTL:       GetTestTokens(t).Get2FATTL(),
				})
				if err != nil {
					t.Fatal("Failed to create email code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertNotEmpty(t, resBody.AccessToken)
				AssertNotEmpty(t, resBody.RefreshToken)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if code is malformed",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newUsername := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountUsername(
					context.Background(),
					services.UpdateAccountUsernameOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Username:  newUsername,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account username: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "not-a-valid-code",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "code", resBody.Fields[0].Param)
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if code is invalid",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, password, newUsername := genTwoFactorAccount(t, services.TwoFactorEmail)
				requestID := uuid.NewString()
				authDTO, serviceErr := GetTestServices(t).UpdateAccountUsername(
					context.Background(),
					services.UpdateAccountUsernameOptions{
						RequestID: requestID,
						PublicID:  account.PublicID,
						Version:   account.Version(),
						Password:  password,
						Username:  newUsername,
					},
				)
				if serviceErr != nil {
					t.Fatalf("failed to update account username: %v", serviceErr)
				}

				return bodies.TwoFactorLoginBody{
					Code: "129876",
				}, authDTO.AccessToken
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if no access token",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				return bodies.TwoFactorLoginBody{
					Code: "123456",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, confirmUsernamePath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}
