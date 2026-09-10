// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/encryptcookie"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
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
	AssertEqual(t, GetTestTokens(t).GetAccessTTL(), resBody.ExpiresIn)
}

func assertTempAccessResponse[T any](t *testing.T, _ T, res *http.Response) {
	resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
	AssertEqual(t, "Bearer", resBody.TokenType)
	AssertNotEmpty(t, resBody.AccessToken)
	AssertEmpty(t, resBody.RefreshToken)
	AssertNotEmpty(t, resBody.Message)
	AssertNotEmpty(t, resBody.ExpiresIn)
}

func assertAuthAccessResponse[T any](t *testing.T, _ T, res *http.Response) {
	resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
	AssertEqual(t, "Bearer", resBody.TokenType)
	AssertNotEmpty(t, resBody.AccessToken)
	AssertNotEmpty(t, resBody.ExpiresIn)
}

func TestConfirm(t *testing.T) {
	const registerPath = "/v1/auth/confirm-email"

	generateConfirmationToken := func(t *testing.T, accountDTO dtos.AccountDTO) bodies.ConfirmationTokenBody {
		testTokens := GetTestTokens(t)
		testServices := GetTestServices(t)
		requestID := uuid.NewString()
		token := testTokens.CreateConfirmationToken(tokens.AccountConfirmationTokenOptions{
			PublicID: accountDTO.PublicID,
			Version:  accountDTO.Version(),
		})

		sToken, serviceErr := GetTestCrypto(t).SignToken(
			context.Background(),
			crypto.SignTokenOptions{
				RequestID: uuid.NewString(),
				Token:     token,
				GetJWKfn: testServices.BuildGetGlobalEncryptedJWKFn(
					context.Background(),
					services.BuildEncryptedJWKFnOptions{
						RequestID: requestID,
						KeyType:   database.TokenKeyTypeEmailVerification,
						TTL:       testTokens.GetConfirmationTTL(),
					},
				),
				GetDecryptDEKfn: testServices.BuildGetGlobalDecDEKFn(
					context.Background(),
					services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
				),
			},
		)
		if serviceErr != nil {
			t.Fatal("Failed to build encrypted JWK function", serviceErr)
		}

		return bodies.ConfirmationTokenBody{ConfirmationToken: sToken}
	}

	testCases := []TestRequestCase[bodies.ConfirmationTokenBody]{
		{
			Name: "Should return 200 OK with access and refresh tokens",
			ReqFn: func(t *testing.T) (bodies.ConfirmationTokenBody, string) {
				return generateConfirmationToken(
					t,
					CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal)),
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
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
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
				account := CreateTestAccount(t, data)
				testS := GetTestServices(t)

				if _, err := testS.CreateAccount2FAConfig(context.Background(), services.CreateAccount2FAConfigOptions{
					RequestID:       uuid.NewString(),
					AccountPublicID: account.PublicID,
					AccountVersion:  account.Version(),
					TwoFAType:       services.TwoFactorTotp,
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
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
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
				data := GenerateFakeAccountData(t, services.AuthProviderLocal)
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
		data := GenerateFakeAccountData(t, services.AuthProviderLocal)
		account := CreateTestAccount(t, data)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		token, err := testS.CreateAccount2FAConfig(context.Background(), services.CreateAccount2FAConfigOptions{
			RequestID:       requestID,
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			TwoFAType:       twoFactorType,
		})
		if err != nil {
			t.Fatal("Failed to enable 2FA", err)
		}

		return account, Account2FAAccessToken(t, token)
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
				requestID := uuid.NewString()
				ctx := context.Background()

				accountTOTP, err := GetTestDatabase(t).FindAccountTotpByAccountID(ctx, account.ID())
				if err != nil {
					t.Fatal("Failed to find account TOTP", err)
				}

				secret, serviceErr := GetTestCrypto(t).DecryptWithDEK(ctx, crypto.DecryptWithDEKOptions{
					RequestID: requestID,
					GetDecryptDEKfn: GetTestServices(t).BuildGetGlobalDecDEKFn(
						ctx,
						services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
					),
					Ciphertext: accountTOTP.Secret,
				})
				if serviceErr != nil {
					t.Fatal("Failed to decrypt TOTP secret", serviceErr)
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
	cookieName := config.CookieName() + "_rt"
	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Host = config.BackendDomain()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	if refreshToken != "" {
		encryptedRefreshToken, err := encryptcookie.EncryptCookie(cookieName, refreshToken, config.CookieSecret())
		if err != nil {
			t.Fatal("Failed to encrypt cookie", err)
		}

		req.AddCookie(&http.Cookie{
			Name:  cookieName,
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, accessToken
			},
			ExpStatus: http.StatusNoContent,
			AssertFn:  func(t *testing.T, _ bodies.RefreshTokenBody, _ *http.Response) {},
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RefreshTokenBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return accessToken, refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {},
		},
		{
			Name:      "Should return 401 UNAUTHORIZED if access token is invalid even if refresh token is passed in a cookie",
			ExpStatus: http.StatusUnauthorized,
			TokenFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
			testServer := GetTestServer(t)

			resp := performCookieRequest(t, testServer.App, logoutPath, accessToken, refreshToken)
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
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
		_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
		testDb := GetTestDatabase(t)
		testTokens := GetTestTokens(t)
		data, err := testTokens.VerifyRefreshToken(refreshToken, GetTestServices(t).BuildGetGlobalPublicKeyFn(
			context.Background(),
			services.BuildGetGlobalVerifyKeyFnOptions{
				RequestID: uuid.NewString(),
				KeyType:   database.TokenKeyTypeRefresh,
			},
		))
		if err != nil {
			t.Fatal("Failed to verify refresh token", err)
		}
		if err := testDb.RevokeToken(context.Background(), database.RevokeTokenParams{
			TokenID:       data.TokenID,
			AccountID:     account.ID(),
			Owner:         database.TokenOwnerAccount,
			OwnerPublicID: account.PublicID,
			IssuedAt:      data.IssuedAt,
			ExpiresAt:     data.ExpiresAt,
		}); err != nil {
			t.Fatal("Failed to blacklist token", err)
		}

		return refreshToken
	}

	testCases := []TestRequestCase[bodies.RefreshTokenBody]{
		{
			Name: "POST should return 200 OK with valid auth response",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
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
			testServer := GetTestServer(t)

			resp := performCookieRequest(t, testServer.App, refreshPath, accessToken, refreshToken)
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

func TestAccount2FARecover(t *testing.T) {
	const recover2FAPath = v1Path + paths.AuthBase + paths.AuthLogin + paths.Auth2FA + paths.Recover

	getRandomZeroToSeven := func() int {
		return rand.Intn(8)
	}

	gen2FAAccount := func(t *testing.T) (dtos.AccountDTO, string, string) {
		data := GenerateFakeAccountData(t, services.AuthProviderLocal)
		accountDTO := CreateTestAccount(t, data)
		testS := GetTestServices(t)
		requestID := uuid.NewString()
		ctx := context.Background()

		configDTO, serviceErr := testS.CreateAccount2FAConfig(ctx, services.CreateAccount2FAConfigOptions{
			RequestID:       requestID,
			AccountPublicID: accountDTO.PublicID,
			AccountVersion:  accountDTO.Version(),
			TwoFAType:       services.TwoFactorTotp,
		})
		if serviceErr != nil {
			t.Fatal("Failed to create TOTP account 2FA config", serviceErr)
		}

		accountDTO, serviceErr = testS.GetAccountByPublicID(ctx, services.GetAccountByPublicIDOptions{
			RequestID: requestID,
			PublicID:  accountDTO.PublicID,
		})
		if serviceErr != nil {
			t.Fatal("Failed to find account by public ID", serviceErr)
		}

		recoveryCode := strings.Split(configDTO.Account2FATOTPConfigDTO.RecoveryKeys, "\n")[getRandomZeroToSeven()]
		return accountDTO, Account2FAAccessToken(t, configDTO), recoveryCode
	}

	testCases := []TestRequestCase[bodies.RecoverBody]{
		{
			Name: "Should return 200 OK and disable 2FA with valid recovery code",
			ReqFn: func(t *testing.T) (bodies.RecoverBody, string) {
				_, token, recoveryCode := gen2FAAccount(t)
				return bodies.RecoverBody{
					RecoveryCode: recoveryCode,
				}, token
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.RecoverBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthDTO{})
				AssertEqual(t, resBody.Message, "Please scan QR Code with your authentication app")
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED with invalid recovery code",
			ReqFn: func(t *testing.T) (bodies.RecoverBody, string) {
				gen2FAAccount(t)
				return bodies.RecoverBody{
					RecoveryCode: "invalid-code",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RecoverBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED without 2FA access token",
			ReqFn: func(t *testing.T) (bodies.RecoverBody, string) {
				_, _, recoveryCode := gen2FAAccount(t)
				return bodies.RecoverBody{
					RecoveryCode: recoveryCode,
				}, "wrong-token"
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RecoverBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, recover2FAPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestAccountAuth2FAConfigs(t *testing.T) {
	const account2FAPath = v1Path + paths.AuthBase + paths.Auth2FA

	genAccountWith2FA := func(t *testing.T, twoFAType string) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGitHub))
		requestID := uuid.NewString()
		if _, serviceErr := GetTestServices(t).CreateAccount2FAConfig(
			context.Background(),
			services.CreateAccount2FAConfigOptions{
				RequestID:       requestID,
				AccountPublicID: account.PublicID,
				AccountVersion:  account.Version(),
				TwoFAType:       twoFAType,
				IsDefault:       true,
			},
		); serviceErr != nil {
			t.Fatalf("failed to create account 2FA config: %v", serviceErr)
		}

		account, serviceErr := GetTestServices(t).GetAccountByPublicID(
			context.Background(),
			services.GetAccountByPublicIDOptions{RequestID: requestID, PublicID: account.PublicID},
		)
		if serviceErr != nil {
			t.Fatalf("failed to reload account: %v", serviceErr)
		}
		accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
		return accessToken
	}

	testCases := []TestRequestCase[bodies.Account2FAConfigBody]{
		{
			Name: "Should create a default TOTP 2FA config",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.Account2FAConfigBody{TwoFAType: services.TwoFactorTotp, IsDefault: true}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.Account2FAConfigBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.Account2FAConfigDTO{})
				AssertEqual(t, database.TwoFactorTypeTotp, resBody.TwoFactorType)
				AssertEqual(t, true, resBody.IsDefault)
				AssertNotEmpty(t, resBody.Account2FATOTPConfigDTO.AccessToken)
				AssertNotEmpty(t, resBody.Account2FATOTPConfigDTO.Image)
				AssertNotEmpty(t, resBody.Account2FATOTPConfigDTO.RecoveryKeys)
			},
		},
		{
			Name: "Should create a default email 2FA config",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderMicrosoft))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.Account2FAConfigBody{TwoFAType: services.TwoFactorEmail, IsDefault: true}, accessToken
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.Account2FAConfigBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.Account2FAConfigDTO{})
				AssertEqual(t, database.TwoFactorTypeEmail, resBody.TwoFactorType)
				AssertEqual(t, true, resBody.IsDefault)
				AssertNotEmpty(t, resBody.Account2FACodeConfigDTO.AccessToken)
			},
		},
		{
			Name: "Should add a second 2FA provider and make it default",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				return bodies.Account2FAConfigBody{TwoFAType: services.TwoFactorTotp, IsDefault: true},
					genAccountWith2FA(t, services.TwoFactorEmail)
			},
			ExpStatus: http.StatusCreated,
			AssertFn: func(t *testing.T, _ bodies.Account2FAConfigBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.Account2FAConfigDTO{})
				AssertEqual(t, database.TwoFactorTypeTotp, resBody.TwoFactorType)
				AssertEqual(t, true, resBody.IsDefault)
			},
		},
		{
			Name: "Should return 409 CONFLICT for an existing 2FA provider",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				return bodies.Account2FAConfigBody{TwoFAType: services.TwoFactorTotp, IsDefault: true},
					genAccountWith2FA(t, services.TwoFactorTotp)
			},
			ExpStatus: http.StatusConflict,
			AssertFn:  AssertConflictError[bodies.Account2FAConfigBody],
		},
		{
			Name: "Should return 400 BAD REQUEST for an invalid 2FA provider",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return bodies.Account2FAConfigBody{TwoFAType: "invalid", IsDefault: true}, accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ bodies.Account2FAConfigBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertNotEmpty(t, len(resBody.Fields))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED without an access token",
			ReqFn: func(t *testing.T) (bodies.Account2FAConfigBody, string) {
				return bodies.Account2FAConfigBody{TwoFAType: services.TwoFactorTotp, IsDefault: true}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.Account2FAConfigBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, account2FAPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestForgotAccountPassword(t *testing.T) {
	const forgotPasswordPath = v1Path + paths.AuthBase + paths.AuthForgotPassword

	testCases := []TestRequestCase[bodies.ForgotPasswordBody]{
		{
			Name: "Should return 200 OK and send reset email for valid email",
			ReqFn: func(t *testing.T) (bodies.ForgotPasswordBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				return bodies.ForgotPasswordBody{Email: account.Email}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.ForgotPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.MessageDTO{})
				AssertEqual(t, resBody.Message, "Reset password email sent if account exists")
			},
		},
		{
			Name: "Should return 200 OK for non-existent email (do not reveal existence)",
			ReqFn: func(t *testing.T) (bodies.ForgotPasswordBody, string) {
				return bodies.ForgotPasswordBody{Email: "nonexistent@example.com"}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.ForgotPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.MessageDTO{})
				AssertEqual(t, resBody.Message, "Reset password email sent if account exists")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST for invalid email format",
			ReqFn: func(t *testing.T) (bodies.ForgotPasswordBody, string) {
				return bodies.ForgotPasswordBody{Email: "not-an-email"}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.ForgotPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "email", resBody.Fields[0].Param)
				AssertEqual(t, exceptions.StrFieldErrMessageEmail, resBody.Fields[0].Message)
				AssertEqual(t, req.Email, resBody.Fields[0].Value.(string))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, forgotPasswordPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestResetAccountPassword(t *testing.T) {
	const resetPasswordPath = v1Path + paths.AuthBase + paths.AuthResetPassword

	generateResetToken := func(t *testing.T, email string) string {
		testTokens := GetTestTokens(t)
		testServices := GetTestServices(t)
		requestID := uuid.NewString()

		account, err := GetTestDatabase(t).FindAccountByEmail(context.Background(), email)
		if err != nil {
			t.Fatal("Failed to find account by email", err)
		}
		token := testTokens.CreateResetToken(tokens.AccountResetTokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version,
		})

		sToken, serviceErr := GetTestCrypto(t).SignToken(
			context.Background(),
			crypto.SignTokenOptions{
				RequestID: requestID,
				Token:     token,
				GetJWKfn: testServices.BuildGetGlobalEncryptedJWKFn(
					context.Background(),
					services.BuildEncryptedJWKFnOptions{
						RequestID: requestID,
						KeyType:   database.TokenKeyTypePasswordReset,
						TTL:       testTokens.GetResetTTL(),
					},
				),
				GetDecryptDEKfn: testServices.BuildGetGlobalDecDEKFn(
					context.Background(),
					services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
				),
			},
		)
		if serviceErr != nil {
			t.Fatal("Failed to sign token", serviceErr)
		}

		return sToken
	}

	testCases := []TestRequestCase[bodies.ResetPasswordBody]{
		{
			Name: "Should return 200 OK and reset password with valid token",
			ReqFn: func(t *testing.T) (bodies.ResetPasswordBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				token := generateResetToken(t, account.Email)
				newPassword := "NewP@ssw0rd123"
				return bodies.ResetPasswordBody{
					ResetToken: token,
					Password:   newPassword,
					Password2:  newPassword,
				}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ bodies.ResetPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.MessageDTO{})
				AssertEqual(t, resBody.Message, "Password reset successfully")
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if token is invalid",
			ReqFn: func(t *testing.T) (bodies.ResetPasswordBody, string) {
				return bodies.ResetPasswordBody{
					ResetToken: "invalid-token",
					Password:   "NewP@ssw0rd123",
					Password2:  "NewP@ssw0rd123",
				}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.ResetPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "reset_token", resBody.Fields[0].Param)
				AssertEqual(t, req.ResetToken, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if password is too weak",
			ReqFn: func(t *testing.T) (bodies.ResetPasswordBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				token := generateResetToken(t, account.Email)
				return bodies.ResetPasswordBody{
					ResetToken: token,
					Password:   "password",
					Password2:  "password",
				}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.ResetPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password", resBody.Fields[0].Param)
				AssertEqual(t, req.Password, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 400 BAD REQUEST if passwords do not match",
			ReqFn: func(t *testing.T) (bodies.ResetPasswordBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				token := generateResetToken(t, account.Email)
				return bodies.ResetPasswordBody{
					ResetToken: token,
					Password:   "NewP@ssw0rd123",
					Password2:  "DifferentP@ssw0rd",
				}, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req bodies.ResetPasswordBody, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "password2", resBody.Fields[0].Param)
				AssertEqual(t, req.Password2, resBody.Fields[0].Value.(string))
			},
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.ResetPasswordBody, string) {
				testTokens := GetTestTokens(t)
				testServices := GetTestServices(t)
				requestID := uuid.NewString()

				token := testTokens.CreateResetToken(tokens.AccountResetTokenOptions{
					PublicID: uuid.New(),
					Version:  1,
				})

				sToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     token,
						GetJWKfn: testServices.BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: uuid.NewString(),
								KeyType:   database.TokenKeyTypePasswordReset,
								TTL:       testTokens.GetResetTTL(),
							},
						),
						GetDecryptDEKfn: testServices.BuildGetGlobalDecDEKFn(
							context.Background(),
							services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to build encrypted JWK function", serviceErr)
				}

				return bodies.ResetPasswordBody{
					ResetToken: sToken,
					Password:   "NewP@ssw0rd123",
					Password2:  "NewP@ssw0rd123",
				}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.ResetPasswordBody],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, resetPasswordPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestListAccountAuthProviders(t *testing.T) {
	const authProvidersPath = v1Path + paths.AuthBase + paths.AuthProviders

	testCases := []TestRequestCase[string]{
		{
			Name: "Should return 200 OK with list of a single auth providers",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return "", accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ItemsDTO[dtos.AuthProviderDTO]{})
				AssertEqual(t, len(resBody.Items), 1)
				AssertEqual(t, resBody.Items[0].Provider, database.AuthProviderLocal)
				AssertNotEmpty(t, resBody.Items[0].RegisteredAt)
			},
		},
		{
			Name: "Should return 200 OK with list of a multiple auth providers",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				testD := GetTestDatabase(t)
				testT := GetTestTokens(t)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				providers := []database.AuthProvider{
					database.AuthProviderMicrosoft,
					database.AuthProviderGoogle,
				}
				for _, provider := range providers {
					if err := testD.CreateAccountAuthProvider(
						context.Background(),
						database.CreateAccountAuthProviderParams{
							Email:           account.Email,
							AccountPublicID: account.PublicID,
							Provider:        provider,
						},
					); err != nil {
						t.Fatalf("Failed to create auth provider: %v", err)
					}
				}

				accessToken, err := testT.CreateAccessToken(tokens.AccountAccessTokenOptions{
					PublicID:     account.PublicID,
					Version:      account.Version(),
					Scopes:       []tokens.AccountScope{tokens.AccountScopeAuthProvidersRead},
					TokenSubject: account.PublicID.String(),
				})
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				sToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     accessToken,
						GetJWKfn: testS.BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: requestID,
								KeyType:   database.TokenKeyTypeAccess,
								TTL:       testT.GetAccessTTL(),
							},
						),
						GetDecryptDEKfn: testS.BuildGetGlobalDecDEKFn(
							context.Background(),
							services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to build encrypted JWK function", serviceErr)
				}

				return "", sToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.ItemsDTO[dtos.AuthProviderDTO]{})
				AssertEqual(t, len(resBody.Items), 3)
				AssertEqual(t, resBody.Items[0].Provider, database.AuthProviderGoogle)
				AssertNotEmpty(t, resBody.Items[0].RegisteredAt)
				AssertEqual(t, resBody.Items[1].Provider, database.AuthProviderMicrosoft)
				AssertNotEmpty(t, resBody.Items[1].RegisteredAt)
				AssertEqual(t, resBody.Items[2].Provider, database.AuthProviderLocal)
				AssertNotEmpty(t, resBody.Items[2].RegisteredAt)
			},
		},
		{
			Name: "Should return 403 forbidden if token has not enough permissions",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				testT := GetTestTokens(t)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				accessToken, err := testT.CreateAccessToken(tokens.AccountAccessTokenOptions{
					PublicID: account.PublicID,
					Version:  account.Version(),
					Scopes: []tokens.AccountScope{
						tokens.AccountScopeCredentialsWrite,
						tokens.AccountScopeCredentialsRead,
					},
					TokenSubject: account.PublicID.String(),
				})
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				sToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     accessToken,
						GetJWKfn: testS.BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: requestID,
								KeyType:   database.TokenKeyTypeAccess,
								TTL:       testT.GetAccessTTL(),
							},
						),
						GetDecryptDEKfn: testS.BuildGetGlobalDecDEKFn(
							context.Background(),
							services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to build encrypted JWK function", serviceErr)
				}

				return "", sToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[string],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if access token is missing",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[string],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, authProvidersPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestGetAccountAuthProvider(t *testing.T) {
	const authProviderPath = v1Path + paths.AuthBase + paths.AuthProviders

	testCases := []TestRequestCase[string]{
		{
			Name: "Should return 200 OK with auth provider details",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderApple))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return "", accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, provider string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthProviderDTO{})
				AssertEqual(t, resBody.Provider, database.AuthProviderApple)
				AssertNotEmpty(t, resBody.RegisteredAt)
			},
			Path: authProviderPath + "/apple",
		},
		{
			Name: "Should return 200 OK with auth provider details if user has correct permissions",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				testT := GetTestTokens(t)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				accessToken, err := testT.CreateAccessToken(tokens.AccountAccessTokenOptions{
					PublicID:     account.PublicID,
					Version:      account.Version(),
					Scopes:       []tokens.AccountScope{tokens.AccountScopeAuthProvidersRead},
					TokenSubject: account.PublicID.String(),
				})
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				sToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     accessToken,
						GetJWKfn: testS.BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: requestID,
								KeyType:   database.TokenKeyTypeAccess,
								TTL:       testT.GetAccessTTL(),
							},
						),
						GetDecryptDEKfn: testS.BuildGetGlobalDecDEKFn(
							context.Background(),
							services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to build encrypted JWK function", serviceErr)
				}

				return "", sToken
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, provider string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, dtos.AuthProviderDTO{})
				AssertEqual(t, resBody.Provider, database.AuthProviderGoogle)
				AssertNotEmpty(t, resBody.RegisteredAt)
			},
			Path: authProviderPath + "/google",
		},
		{
			Name: "Should return 404 NOT FOUND for non-existent auth provider",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return "", accessToken
			},
			ExpStatus: http.StatusNotFound,
			AssertFn:  AssertNotFoundError[string],
			Path:      authProviderPath + "/facebook",
		},
		{
			Name: "Should return 400 BAD REQUEST for an invalid auth provider",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGitHub))
				accessToken, _ := GenerateTestAccountAuthTokens(t, &account)
				return "", accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, resBody.Message, "Invalid request")
				AssertEqual(t, len(resBody.Fields), 1)
				AssertEqual(t, resBody.Fields[0].Param, "provider")
				AssertEqual(t, resBody.Fields[0].Value, "unknown")
				AssertEqual(t, resBody.Fields[0].Message, "must be valid")
			},
			Path: authProviderPath + "/unknown",
		},
		{
			Name: "Should return 403 forbidden if token has not enough permissions",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderMicrosoft))
				testT := GetTestTokens(t)
				testS := GetTestServices(t)
				requestID := uuid.NewString()

				accessToken, err := testT.CreateAccessToken(tokens.AccountAccessTokenOptions{
					PublicID:     account.PublicID,
					Version:      account.Version(),
					Scopes:       []tokens.AccountScope{tokens.AccountScopeAppsRead},
					TokenSubject: account.PublicID.String(),
				})
				if err != nil {
					t.Fatalf("Failed to create access token: %v", err)
				}

				sToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     accessToken,
						GetJWKfn: testS.BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: requestID,
								KeyType:   database.TokenKeyTypeAccess,
								TTL:       testT.GetAccessTTL(),
							},
						),
						GetDecryptDEKfn: testS.BuildGetGlobalDecDEKFn(
							context.Background(),
							services.BuildGetGlobalDEKFnOptions{RequestID: requestID},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to build encrypted JWK function", serviceErr)
				}

				return "", sToken
			},
			ExpStatus: http.StatusForbidden,
			AssertFn:  AssertForbiddenError[string],
			Path:      authProviderPath + "/github",
		},
		{
			Name: "Should return 401 UNAUTHORIZED if access token is missing",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[string],
			Path:      authProviderPath + "/username_password",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, tc.Path, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}
