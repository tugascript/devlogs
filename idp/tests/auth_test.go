package tests

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"github.com/tugascript/devlogs/idp/internal/utils"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-faker/faker/v4"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/encryptcookie"
	"github.com/google/uuid"
	"github.com/h2non/gock"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
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
			Email:     fakeData.Email,
			FirstName: fakeData.FirstName,
			LastName:  fakeData.LastName,
			Password:  fakeData.Password,
			Password2: fakeData.Password,
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

func assertAuthAccessResponse[T any](t *testing.T, _ T, res *http.Response) {
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
		token, err := testTokens.CreateConfirmationToken(tokens.AccountTokenOptions{
			ID:      accountDTO.ID,
			Version: accountDTO.Version(),
			Email:   accountDTO.Email,
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
					CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail)),
				), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[bodies.ConfirmationTokenBody],
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				return generateConfirmationToken(t, dtos.AccountDTO{
					ID:        account.ID,
					FirstName: account.FirstName,
					LastName:  account.LastName,
					Email:     account.Email,
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
				data := GenerateFakeAccountData(t, services.AuthProviderEmail)
				account := CreateTestAccount(t, data)
				return bodies.LoginBody{
					Email:    account.Email,
					Password: data.Password,
				}, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[bodies.LoginBody],
		},
		{
			Name: "Should return 200 OK with temporary access token if user has 2FA enabled",
			ReqFn: func(t *testing.T) (bodies.LoginBody, string) {
				data := GenerateFakeAccountData(t, services.AuthProviderEmail)
				account := CreateTestAccount(t, data)
				testS := GetTestServices(t)

				if _, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
					RequestID:     uuid.NewString(),
					ID:            int32(account.ID),
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
				data := GenerateFakeAccountData(t, services.AuthProviderEmail)
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
				data := GenerateFakeAccountData(t, services.AuthProviderEmail)
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
		data := GenerateFakeAccountData(t, services.AuthProviderEmail)
		account := CreateTestAccount(t, data)
		testS := GetTestServices(t)
		requestID := uuid.NewString()

		token, err := testS.UpdateAccount2FA(context.Background(), services.UpdateAccount2FAOptions{
			RequestID:     requestID,
			ID:            int32(account.ID),
			TwoFactorType: twoFactorType,
			Password:      data.Password,
		})
		if err != nil {
			t.Fatal("Failed to enable 2FA", err)
		}

		return account, token.AccessToken
	}

	genEmailCode := func(t *testing.T, account dtos.AccountDTO) string {
		testCache := GetTestCache(t)
		code, err := testCache.AddTwoFactorCode(context.Background(), cache.AddTwoFactorCodeOptions{
			RequestID: uuid.NewString(),
			AccountID: account.ID,
		})
		if err != nil {
			t.Fatal("Failed to create email code", err)
		}
		return code
	}

	testCases := []TestRequestCase[bodies.TwoFactorLoginBody]{
		{
			Name: "Should return 200 OK with access and refresh tokens",
			ReqFn: func(t *testing.T) (bodies.TwoFactorLoginBody, string) {
				account, token := genTwoFactorAccount(t, services.TwoFactorEmail)
				return bodies.TwoFactorLoginBody{
					Code: genEmailCode(t, account),
				}, token
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[bodies.TwoFactorLoginBody],
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, accessToken
			},
			ExpStatus: http.StatusNoContent,
			AssertFn:  func(t *testing.T, _ bodies.RefreshTokenBody, _ *http.Response) {},
		},
		{
			Name: "Should return 400 BAD REQUEST if request validation fails",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return bodies.RefreshTokenBody{RefreshToken: refreshToken}, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  AssertUnauthorizedError[bodies.RefreshTokenBody],
		},
		{
			Name: "Should return 401 UNAUTHORIZED if user is not found",
			ReqFn: func(t *testing.T) (bodies.RefreshTokenBody, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				account.ID = 10000000
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
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				accessToken, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return accessToken, refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {},
		},
		{
			Name:      "Should return 401 UNAUTHORIZED if access token is invalid even if refresh token is passed in a cookie",
			ExpStatus: http.StatusUnauthorized,
			TokenFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderEmail))
				_, refreshToken := GenerateTestAccountAuthTokens(t, &account)
				return "invalid", refreshToken
			},
			AssertFn: func(t *testing.T, resp *http.Response) {
				AssertUnauthorizedError[string](t, "", resp)
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

func TestAccountOAuthURL(t *testing.T) {
	const oauth2Path = "/v1/auth/oauth2"

	testCases := []TestRequestCase[string]{
		{
			Name: "GET Apple should return URL and 302 FOUND",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "https://appleid.apple.com/auth/authorize")
			},
			Path: oauth2Path + "/apple",
		},
		{
			Name: "GET Facebook should return URL and 302 FOUND",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "https://www.facebook.com/v3.2/dialog/oauth")
			},
			Path: oauth2Path + "/facebook",
		},
		{
			Name: "GET GitHub should return URL and 302 FOUND",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "https://github.com/login/oauth/authorize")
			},
			Path: oauth2Path + "/github",
		},
		{
			Name: "GET Google should return URL and 302 FOUND",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "https://accounts.google.com/o/oauth2/auth")
			},
			Path: oauth2Path + "/google",
		},
		{
			Name: "GET Microsoft should return URL and 302 FOUND",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "https://login.live.com/oauth20_authorize.srf")
			},
			Path: oauth2Path + "/microsoft",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, tc.Path, tc)
		})
	}
}

func generateCode(t *testing.T) string {
	const codeLength = 6
	const digits = "0123456789"
	code := make([]byte, codeLength)

	for i := 0; i < codeLength; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			t.Fatal("Failed to generate code", err)
		}
		code[i] = digits[num.Int64()]
	}

	return string(code)
}

func generateState(t *testing.T) string {
	bytes := make([]byte, 16)

	if _, err := rand.Read(bytes); err != nil {
		t.Fatal("Failed to generate state", err)
	}

	return hex.EncodeToString(bytes)
}

func callbackBeforeEach(t *testing.T, provider string) (string, string, string) {
	ctx := context.Background()

	email := utils.Lowered(faker.Email())
	state := generateState(t)

	testCache := GetTestCache(t)
	requestID := uuid.NewString()
	stateOpts := cache.AddOAuthStateOptions{
		RequestID: requestID,
		State:     state,
		Provider:  provider,
	}
	if err := testCache.AddOAuthState(ctx, stateOpts); err != nil {
		t.Fatalf("Error adding state to cache: %v", err)
	}

	code, err := testCache.GenerateOAuthCode(ctx, cache.GenerateOAuthOptions{
		RequestID:       requestID,
		Email:           email,
		DurationSeconds: GetTestTokens(t).GetOAuthTTL(),
	})
	if err != nil {
		t.Fatalf("Error generating OAuth code: %v", err)
	}

	return email, code, state
}

func TestOAuthCallback(t *testing.T) {
	defer gock.OffAll()
	const oauth2Path = "/v1/auth/oauth2"

	var email, code, state string
	addParams := func(t *testing.T) string {
		params := make(url.Values)
		params.Add("code", code)
		params.Add("state", state)
		return params.Encode()
	}

	testCases := []TestRequestCase[string]{
		{
			Name: "GET facebook callback should return 302 FOUND and redirect code",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderFacebook)
				gock.New("https://graph.facebook.com").
					Post("/v3.2/oauth/access_token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				gock.New("https://graph.facebook.com/").
					Get("v22.0/me").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"name":       "John Doe",
						"first_name": "John",
						"last_name":  "Doe",
						"email":      email,
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_token")
				AssertStringContains(t, location, "token_type")
				AssertStringContains(t, location, "expires_in")
				AssertEqual(t, gock.IsDone(), true)
			},
			PathFn: func() string {
				return oauth2Path + "/facebook/callback?" + addParams(t)
			},
		},
		{
			Name: "GET github callback should return 302 FOUND and redirect code",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderGitHub)
				gock.New("https://github.com").
					Post("/login/oauth/access_token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				gock.New("https://api.github.com").
					Get("/user").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"name":     "John Doe",
						"location": "nz",
						"email":    email,
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_token")
				AssertStringContains(t, location, "token_type")
				AssertStringContains(t, location, "expires_in")
				AssertEqual(t, gock.IsDone(), true)
			},
			PathFn: func() string {
				return oauth2Path + "/github/callback?" + addParams(t)
			},
		},
		{
			Name: "GET google callback should return 302 FOUND and redirect code",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderGoogle)
				gock.New("https://oauth2.googleapis.com").
					Post("/token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				gock.New("https://www.googleapis.com").
					Get("/oauth2/v3/userinfo").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"name":           "John Doe",
						"given_name":     "John",
						"family_name":    "Doe",
						"locale":         "EN_NZ",
						"email_verified": true,
						"email":          email,
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				defer gock.OffAll()
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_token")
				AssertStringContains(t, location, "token_type")
				AssertStringContains(t, location, "expires_in")
				AssertEqual(t, gock.IsDone(), true)
			},
			PathFn: func() string {
				return oauth2Path + "/google/callback?" + addParams(t)
			},
		},
		{
			Name: "GET google callback should return 302 FOUND and access denied if the user is not verified",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderGoogle)
				gock.New("https://oauth2.googleapis.com").
					Post("/token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				gock.New("https://www.googleapis.com").
					Get("/oauth2/v3/userinfo").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"name":           "John Doe",
						"given_name":     "John",
						"family_name":    "Doe",
						"locale":         "EN_NZ",
						"email_verified": false,
						"email":          email,
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_denied")
				defer gock.OffAll()
			},
			PathFn: func() string {
				return oauth2Path + "/google/callback?" + addParams(t)
			},
		},
		{
			Name: "GET microsoft callback should return 302 FOUND and redirect code",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderMicrosoft)
				gock.New("https://login.microsoftonline.com").
					Post("/common/oauth2/v2.0/token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				gock.New("https://graph.microsoft.com").
					Get("/v1.0/me").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"displayName": "John Doe",
						"givenName":   "John",
						"surname":     "Doe",
						"mail":        email,
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_token")
				AssertStringContains(t, location, "token_type")
				AssertStringContains(t, location, "expires_in")
				AssertEqual(t, gock.IsDone(), true)
				defer gock.OffAll()
			},
			PathFn: func() string {
				return oauth2Path + "/microsoft/callback?" + addParams(t)
			},
		},
		{
			Name: "GET random should return 400 BAD REQUEST when the provider is not valid",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.ValidationErrorResponse{})
				AssertEqual(t, 1, len(resBody.Fields))
				AssertEqual(t, "provider", resBody.Fields[0].Param)
				AssertEqual(t, "random", resBody.Fields[0].Value.(string))
			},
			PathFn: func() string {
				return oauth2Path + "/random/callback?" + addParams(t)
			},
		},
		{
			Name: "GET microsoft callback should return 302 FOUND and access_denied if the external provider respons with 401",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderMicrosoft)
				gock.New("https://login.microsoftonline.com").
					Post("/common/oauth2/v2.0/token").
					Reply(http.StatusUnauthorized).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
					})

				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_denied")
				defer gock.OffAll()
			},
			PathFn: func() string {
				return oauth2Path + "/microsoft/callback?" + addParams(t)
			},
		},
		{
			Name: "GET microsoft callback should return 302 FOUND and invalid request if the state is invalid",
			ReqFn: func(t *testing.T) (string, string) {
				email, code, state = callbackBeforeEach(t, services.AuthProviderMicrosoft)
				state = "invalid"
				return "", ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ string, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "invalid_request")
				defer gock.OffAll()
			},
			PathFn: func() string {
				return oauth2Path + "/microsoft/callback?" + addParams(t)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWithPathFn(t, http.MethodGet, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

//type appleFakeUserName struct {
//	FirstName string `json:"firstName" faker:"first_name"`
//	LastName  string `json:"lastName" faker:"last_name"`
//}
//
//type appleFakeUser struct {
//	Name  appleFakeUserName `json:"name"`
//	Email string            `json:"email" faker:"email"`
//}
//
//func generateFakeAppleData(t *testing.T) bodies.AppleLoginBody {
//	fakeUserData := appleFakeUser{}
//	if err := faker.FakeData(&fakeUserData); err != nil {
//		t.Fatal("Failed to generate fake user data", err)
//	}
//
//	userJson, err := json.Marshal(fakeUserData)
//	if err != nil {
//		t.Fatal("Failed to marshal user data", err)
//	}
//
//	return bodies.AppleLoginBody{
//		Code:  generateCode(t),
//		State: generateState(t),
//		User:  string(userJson),
//	}
//}
//
