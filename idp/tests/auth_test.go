// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/encryptcookie"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/pquerna/otp/totp"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type fakeRegisterData struct {
	Email     string `faker:"email"`
	FirstName string `faker:"first_name"`
	LastName  string `faker:"last_name"`
	Password  string `faker:"oneof: Pas@w0rd123, P@sW0rd456, P@ssw0rd789, P@ssW0rd012, P@ssw0rd!345"`
}

func accountsCleanUp(t *testing.T) func() {
	return func() {
		db := GetTestDatabase(t)
		cc := GetTestCache(t)

		if err := db.DeleteAllAccounts(context.Background()); err != nil {
			t.Fatal("Failed to delete all accounts", err)
		}
		if err := cc.ResetCache(); err != nil {
			t.Fatal("Failed to reset cache", err)
		}
	}
}

func TestRegister(t *testing.T) {
	const registerPath = "/v1/auth/register"

	generateFakeRegisterData := func(t *testing.T) bodies.RegisterAccountBody {
		fakeData := fakeRegisterData{}
		if err := faker.FakeData(&fakeData); err != nil {
			t.Fatal("Failed to generate fake data", err)
		}
		return bodies.RegisterAccountBody{
			Email:      fakeData.Email,
			GivenName:  fakeData.FirstName,
			FamilyName: fakeData.LastName,
			Password:   fakeData.Password,
			Password2:  fakeData.Password,
		}
	}

	testCases := []TestRequestCase[bodies.RegisterAccountBody]{
		{
			Name: "Should return 200 OK registering a user",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				return generateFakeRegisterData(t), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.MessageDTO{})
				AssertEqual(
					t,
					"Account registered successfully. Confirmation email has been sent.",
					resBody.Message,
				)
				AssertNotEmpty(t, resBody.ID)
			},
		},
		{
			Name: "Should return 200 OK registering a user with username",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				data := generateFakeRegisterData(t)
				random, err := utils.GenerateBase32Secret(16)
				if err != nil {
					t.Fatal("Failed to generate random username", err)
				}
				data.Username = utils.Lowered(random)
				return data, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, body bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.MessageDTO{})
				AssertEqual(
					t,
					"Account registered successfully. Confirmation email has been sent.",
					resBody.Message,
				)
				AssertNotEmpty(t, resBody.ID)
				count, err := GetTestDatabase(t).CountAccountsByUsername(context.Background(), body.Username)
				if err != nil {
					t.Fatal("Failed to count accounts by username", err)
				}
				AssertEqual(t, int64(1), count)
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				data := generateFakeRegisterData(t)
				data.Email = "notAnEmail"
				return data, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "email", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.StrFieldErrMessageEmail, resBody.Fields[0].Message)
				AssertEqual(t, req.Email, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if request password is too week",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				data := generateFakeRegisterData(t)
				invalidPass := "PasswordPassword"
				data.Password = invalidPass
				data.Password2 = invalidPass
				return data, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.StrFieldErrMessagePassword, resBody.Fields[0].Message)
				AssertEqual(t, req.Password, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if password and password2 do not match",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				data := generateFakeRegisterData(t)
				invalidPass := "PasswordPassword"
				data.Password2 = invalidPass
				return data, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password2", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.FieldErrMessageEqField, resBody.Fields[0].Message)
				AssertEqual(t, req.Password2, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 409 CONFLICT if email is already taken",
			ReqFn: func(t *testing.T) (bodies.RegisterAccountBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				data := generateFakeRegisterData(t)
				data.Email = account.Email
				return data, ""
			},
			ExpStatus: http.StatusConflict,
			AssertFn: func(t *testing.T, req bodies.RegisterAccountBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
				AssertEqual(t, "Email already in use", resBody.Message)
				AssertEqual(t, exceptions.StatusConflict, resBody.Code)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, registerPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func assertFullAuthAccessResponse[T any](t *testing.T, _ T, res *http.Response) {
	resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
	AssertEqual(t, "Bearer", resBody.TokenType)
	AssertNotEmpty(t, resBody.AccessToken)
	AssertNotEmpty(t, resBody.RefreshToken)
	AssertEqual(t, GetTestTokens(t).GetAccessTTL(), int64(resBody.ExpiresIn))
}

func assertTempAccessResponse[T any](t *testing.T, _ T, res *http.Response) {
	resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
	AssertEqual(t, "Bearer", resBody.TokenType)
	AssertNotEmpty(t, resBody.AccessToken)
	AssertEmpty(t, resBody.RefreshToken)
	AssertNotEmpty(t, resBody.Message)
	AssertNotEmpty(t, resBody.ExpiresIn)
}

func TestConfirm(t *testing.T) {
	const registerPath = "/v1/auth/confirm-email"

	generateConfirmationToken := func(t *testing.T, accountDTO dtos.AccountDTO) bodies.ConfirmationTokenBody {
		testTokens := GetTestTokens(t)
		token, err := testTokens.CreateConfirmationToken(tokens.AccountConfirmationTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		})
		if err != nil {
			t.Fatal("Failed to create confirmation token", err)
		}

		return bodies.ConfirmationTokenBody{ConfirmationToken: token}
	}

	testCases := []TestRequestCase[bodies.ConfirmationTokenBody]{
		{
			Name: "Should return 200 OK with access and refresh tokens",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				return generateConfirmationToken(
					t,
					CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)),
				), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[bodies.ConfirmationTokenBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if confirmation token is invalid",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				return bodies.ConfirmationTokenBody{ConfirmationToken: "invalidToken"}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.ConfirmationTokenBody, resp *http.Response) {
				resBody := AssertTestResponseBody(t, resp, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "confirmation_token", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.StrFieldErrMessageJWT, resBody.Fields[0].Message)
				AssertEqual(t, req.ConfirmationToken, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				return generateConfirmationToken(t, dtos.AccountDTO{}), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.ConfirmationTokenBody],
		},
		{
			Name: "Should return 409 FORBIDDEN if user is already confirmed",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				return generateConfirmationToken(
					t,
					CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle)),
				), ""
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[bodies.ConfirmationTokenBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user version mismatch",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				return generateConfirmationToken(t, dtos.AccountDTO{
					PublicID:   account.PublicID,
					GivenName:  account.GivenName,
					FamilyName: account.FamilyName,
					Email:      account.Email,
				}), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.ConfirmationTokenBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, registerPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestLogin(t *testing.T) {
	const loginPath = "/v1/auth/login"

	testCases := []TestRequestCase[bodies.LoginBody]{
		{
			Name: "Should return 200 OK with access and refresh tokens",
			ReqFn: func(t *testing.T) (bodies.LoginBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)
				account := CreateTestAccount(t, data)
				return bodies.LoginBody{
					Email:    account.Email,
					Password: data.Password,
				}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[bodies.LoginBody],
		},
		{
			Name: "Should return 200 OK with temporary access token if user has 2FA enabled",
			ReqFn: func(t *testing.T) (bodies.LoginBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)
				account := CreateTestAccount(t, data)
				testS := GetTestServices(t)

				if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
					RequestID:     uuid.NewString(),
					PublicID:      account.PublicID,
					Version:       account.Version(),
					TwoFactorType: services.TwoFactorTotp,
					Password:      data.Password,
				}); err != nil {
					t.Fatal("Failed to enable 2FA", err)
				}

				return bodies.LoginBody{
					Email:    account.Email,
					Password: data.Password,
				}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertTempAccessResponse[bodies.LoginBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.LoginBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)
				return bodies.LoginBody{
					Email:    "not-an-email",
					Password: data.Password,
				}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.LoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "email", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.StrFieldErrMessageEmail, resBody.Fields[0].Message)
				AssertEqual(t, req.Email, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.LoginBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)
				return bodies.LoginBody{
					Email:    data.Email,
					Password: data.Password,
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.LoginBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, loginPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestTwoFactorLogin(t *testing.T) {
	const login2FAPath = "/v1/auth/login/2fa"

	genTwoFactorAccount := func(t *testing.T, twoFactorType string) (dtos.AccountDTO, string) {
		data := GenerateFakeAccountData(t, services.AuthProviderUsernamePassword)
		account := CreateTestAccount(t, data)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		token, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
			RequestID:     requestID,
			PublicID:      account.PublicID,
			Version:       account.Version(),
			TwoFactorType: twoFactorType,
			Password:      data.Password,
		})
		if err != nil {
			t.Fatal("Failed to enable 2FA", err)
		}

		return account, token.AccessToken
	}

	genEmailCode := func(t *testing.T, account dtos.AccountDTO) string {
		code, err := GetTestCache(t).AddTwoFactorCode(context.Background(), cache.AddTwoFactorCodeOptions{
			RequestID: uuid.NewString(),
			AccountID: account.ID(),
			TTL:       GetTestTokens(t).Get2FATTL(),
		})
		if err != nil {
			t.Fatal("Failed to create email code", err)
		}
		return code
	}

	testCases := []TestRequestCase[bodies.TwoFactorLoginBody]{
		{
			Name: "Should return 200 OK with access and refresh tokens for TOTP 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, token := genTwoFactorAccount(t, services.TwoFactorTotp)
				accountTOTP, err := GetTestDatabase(t).FindAccountTotpByAccountID(context.Background(), account.ID())
				if err != nil {
					t.Fatal("Failed to find account TOTP", err)
				}

				dek, _, err := GetTestEncryption(t).ProcessTotpDEK(context.Background(),
					encryption.ProcessTotpDEKOptions{
						RequestID: uuid.NewString(),
						TotpType:  encryption.TotpTypeAccount,
						StoredDEK: account.DEK(),
					},
				)
				if err != nil {
					t.Fatal("Failed to decrypt account DEK", err)
				}

				secret, err := utils.Decrypt(accountTOTP.Secret, dek)
				if err != nil {
					t.Fatal("Failed to decrypt secret", err)
				}

				code, err := totp.GenerateCode(secret, time.Now().UTC())
				if err != nil {
					t.Fatal("Failed to generate code", err)
				}

				return bodies.TwoFactorLoginBody{
					Code: code,
				}, token
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[bodies.TwoFactorLoginBody],
		},
		{
			Name: "Should return 200 OK with access and refresh tokens for email 2FA",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, token := genTwoFactorAccount(t, services.TwoFactorEmail)
				return bodies.TwoFactorLoginBody{Code: genEmailCode(t, account)}, token
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[bodies.TwoFactorLoginBody],
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				_, token := genTwoFactorAccount(t, services.TwoFactorEmail)
				return bodies.TwoFactorLoginBody{Code: "invalidCode"}, token
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.TwoFactorLoginBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "code", resBody.Fields[0].Param)
				AssertEqual(t, req.Code, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user does not have a 2FA access token",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, _ := genTwoFactorAccount(t, services.TwoFactorEmail)
				return bodies.TwoFactorLoginBody{Code: genEmailCode(t, account)}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.TwoFactorLoginBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, login2FAPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

type cookieTestCase struct {
	Name      string
	ExpStatus int
	TokenFn   func(t *testing.T) (string, string)
	AssertFn  func(t *testing.T, resp *http.Response)
}

func performCookieRequest(t *testing.T, app *fiber.App, path, accessToken, refreshToken string) *http.Response {
	config := GetTestConfig(t)
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if refreshToken != "" {
		encryptedRefreshToken, err := encryptcookie.EncryptCookie(refreshToken, config.CookieSecret())
		if err != nil {
			t.Fatal("Failed to encrypt cookie", err)
		}

		req.AddCookie(&http.Cookie{
			Name:  config.CookieName(),
			Value: encryptedRefreshToken,
			Path:  "/api/auth",
		})
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal("Failed to perform request", err)
	}

	return resp
}

func TestLogoutAccount(t *testing.T) {
	const logoutPath = "/v1/auth/logout"

	testCases := []TestRequestCase[bodies.RefreshTokenBody]{
		{
			Name: "Should return 204 NO CONTENT",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, accessToken
			},
			ExpStatus: http.StatusNoContent,
			AssertFn:  func(t *testing.T, _ bodies.RefreshTokenBody, _ *http.Response) {},
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: "not-valid-token"}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RefreshTokenBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "refresh_token", resBody.Fields[0].Param)
				AssertEqual(t, req.RefreshToken, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: "not-valid-token"}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RefreshTokenBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "refresh_token", resBody.Fields[0].Param)
				AssertEqual(t, req.RefreshToken, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user has no access token",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RefreshTokenBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				account.PublicID = uuid.New()
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RefreshTokenBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, logoutPath, tc)
		})
	}

	cookieTestCases := []cookieTestCase{
		{
			Name:      "Should return 204 NO CONTENT when refresh token is passed in a cookie",
			ExpStatus: http.StatusNoContent,
			TokenFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return accessToken, refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {},
		},
		{
			Name:      "Should return 401 UNAUTHORIZED if access token is invalid even if refresh token is passed in a cookie",
			ExpStatus: http.StatusUnauthorized,
			TokenFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return "invalid", refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {
				AssertUnauthorizedError(t, "", resp)
			},
		},
	}

	for _, tc := range cookieTestCases {
		t.Run(tc.Name, func(t *testing.T) {
			accessToken, refreshToken := tc.TokenFn(t)
			server := GetTestServer(t)

			resp := performCookieRequest(t, server.App, logoutPath, accessToken, refreshToken)
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			AssertTestStatusCode(t, resp, tc.ExpStatus)
			tc.AssertFn(t, resp)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestRefreshToken(t *testing.T) {
	const refreshPath = "/v1/auth/refresh"

	generateBlackListToken := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
		_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
		testDb := GetTestDatabase(t)
		testTokens := GetTestTokens(t)
		_, _, id, exp, err := testTokens.VerifyRefreshToken(refreshToken)
		if err != nil {
			t.Fatal("Failed to verify refresh token", err)
		}
		var expiresAt pgtype.Timestamp
		if err := expiresAt.Scan(exp); err != nil {
			t.Fatal("Failed to scan expiresAt", err)
		}
		if err := testDb.RevokeToken(context.Background(), database.RevokeTokenParams{
			TokenID:   id,
			ExpiresAt: expiresAt.Time,
		}); err != nil {
			t.Fatal("Failed to blacklist token", err)
		}

		return refreshToken
	}

	testCases := []TestRequestCase[bodies.RefreshTokenBody]{
		{
			Name: "POST should return 200 OK with valid auth response",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[bodies.RefreshTokenBody],
		},
		{
			Name: "POST should return 400 BAD REQUEST with invalid refresh token",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				return bodies.RefreshTokenBody{RefreshToken: "not-token"}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.RefreshTokenBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "refresh_token", resBody.Fields[0].Param)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED with blacklisted refresh token",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				refreshToken := generateBlackListToken(t)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RefreshTokenBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, refreshPath, tc)
		})
	}

	cookieTestCases := []cookieTestCase{
		{
			Name:      "Should return 200 OK when refresh token is passed in a cookie",
			ExpStatus: http.StatusOK,
			TokenFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderUsernamePassword))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return "", refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {
				assertFullAuthAccessResponse(t, "", resp)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED with blacklisted refresh token in a cookie",
			TokenFn: func(t *testing.T) (string, string) {
				refreshToken := generateBlackListToken(t)
				return "", refreshToken
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, res *http.Response) {
				AssertUnauthorizedError(t, "", res)
			},
		},
	}

	for _, tc := range cookieTestCases {
		t.Run(tc.Name, func(t *testing.T) {
			accessToken, refreshToken := tc.TokenFn(t)
			server := GetTestServer(t)

			resp := performCookieRequest(t, server.App, refreshPath, accessToken, refreshToken)
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			AssertTestStatusCode(t, resp, tc.ExpStatus)
			tc.AssertFn(t, resp)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

// TODO: add tests for account 2fa recovery
// TODO: add tests for account forgot password and reset password
// TODO: add tests for list and get auth providers
