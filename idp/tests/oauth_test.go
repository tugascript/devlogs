// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/h2non/gock"

	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

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
				AssertStringContains(t, location, "https://login.microsoftonline.com/common/oauth2/v2.0/authorize")
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
	addParams := func() string {
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
				return oauth2Path + "/facebook/callback?" + addParams()
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
				return oauth2Path + "/github/callback?" + addParams()
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
				return oauth2Path + "/google/callback?" + addParams()
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
				return oauth2Path + "/google/callback?" + addParams()
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
				return oauth2Path + "/microsoft/callback?" + addParams()
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
				return oauth2Path + "/random/callback?" + addParams()
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
				return oauth2Path + "/microsoft/callback?" + addParams()
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
				return oauth2Path + "/microsoft/callback?" + addParams()
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

type appleFakeUserName struct {
	FirstName string `json:"firstName" faker:"first_name"`
	LastName  string `json:"lastName" faker:"last_name"`
}

type appleFakeUser struct {
	Name  appleFakeUserName `json:"name"`
	Email string            `json:"email" faker:"email"`
}

func generateFakeAppleData(t *testing.T) (bodies.AppleLoginBody, string) {
	fakeUserData := appleFakeUser{}
	if err := faker.FakeData(&fakeUserData); err != nil {
		t.Fatal("Failed to generate fake user data", err)
	}

	userJson, err := json.Marshal(fakeUserData)
	if err != nil {
		t.Fatal("Failed to marshal user data", err)
	}

	return bodies.AppleLoginBody{
		Code:  generateCode(t),
		State: generateState(t),
		User:  string(userJson),
	}, fakeUserData.Email
}

func TestAppleCallback(t *testing.T) {
	defer gock.OffAll()
	const appleOAuth2Path = "/v1/auth/oauth2/apple/callback"

	testCases := []TestRequestCase[bodies.AppleLoginBody]{
		{
			Name: "POST should return 302 FOUND and redirect code",
			ReqFn: func(t *testing.T) (bodies.AppleLoginBody, string) {
				_, code, state := callbackBeforeEach(t, services.AuthProviderApple)
				fakeData, fakeEmail := generateFakeAppleData(t)
				fakeData.Code = code
				fakeData.State = state

				privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal("Failed to generate RSA key for testing", err)
				}

				// Create a token with RSA signing method
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"sub":            "123456.abcdef",
					"email":          fakeEmail,
					"email_verified": true,
					"iss":            "https://appleid.apple.com",
					"aud":            "apple",
					"exp":            time.Now().Add(time.Hour).Unix(),
					"iat":            time.Now().Unix(),
				})
				token.Header["kid"] = "test-kid" // Set a test key ID

				// Sign the token with the RSA private key
				tokenString, err := token.SignedString(privateKey)
				if err != nil {
					t.Fatal("Failed to sign test token", err)
				}

				// Create and encode RSA public key as JWK
				rsaJWK := utils.RS256JWK{
					Kty: "RSA",
					Kid: "test-kid",
					Use: "sig",
					Alg: "RS256",
					N:   base64.RawURLEncoding.EncodeToString(privateKey.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // Standard RSA exponent 65537
				}

				gock.New("https://appleid.apple.com").
					Post("/auth/token").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"access_token":  "123",
						"token_type":    "Bearer",
						"expires_in":    3600,
						"refresh_token": "456",
						"id_token":      tokenString,
					})

				// Mock Apple's JWKS endpoint
				gock.New("https://appleid.apple.com").
					Get("/auth/keys").
					Reply(http.StatusOK).
					JSON(map[string]interface{}{
						"keys": []utils.RS256JWK{rsaJWK},
					})

				return fakeData, ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ bodies.AppleLoginBody, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_token")
				AssertStringContains(t, location, "token_type")
				AssertStringContains(t, location, "expires_in")
				AssertEqual(t, gock.IsDone(), true)
			},
		},
		{
			Name: "POST should return 302 FOUND and access_denied if the external provider responds with 401",
			ReqFn: func(t *testing.T) (bodies.AppleLoginBody, string) {
				_, code, state := callbackBeforeEach(t, services.AuthProviderApple)
				fakeData, _ := generateFakeAppleData(t)
				fakeData.Code = code
				fakeData.State = state

				gock.New("https://appleid.apple.com").
					Post("/auth/token").
					Reply(http.StatusUnauthorized)

				return fakeData, ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ bodies.AppleLoginBody, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "access_denied")
			},
		},
		{
			Name: "POST should return 302 FOUND and invalid_request if the state is invalid",
			ReqFn: func(t *testing.T) (bodies.AppleLoginBody, string) {
				fakeData, _ := generateFakeAppleData(t)
				fakeData.State = "invalid"
				return fakeData, ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ bodies.AppleLoginBody, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "invalid_request")
			},
		},
		{
			Name: "POST should return 302 FOUND and invalid_request if the user data is invalid",
			ReqFn: func(t *testing.T) (bodies.AppleLoginBody, string) {
				_, code, state := callbackBeforeEach(t, services.AuthProviderApple)
				fakeData, _ := generateFakeAppleData(t)
				fakeData.Code = code
				fakeData.State = state
				fakeData.User = "invalid json"

				return fakeData, ""
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ bodies.AppleLoginBody, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "invalid_request")
			},
		},
		{
			Name: "POST should return 400 BAD REQUEST if the content type is not form-urlencoded",
			ReqFn: func(t *testing.T) (bodies.AppleLoginBody, string) {
				fakeData, _ := generateFakeAppleData(t)
				return fakeData, "application/json"
			},
			ExpStatus: http.StatusFound,
			AssertFn: func(t *testing.T, _ bodies.AppleLoginBody, res *http.Response) {
				location := res.Header.Get("Location")
				AssertNotEmpty(t, location)
				AssertStringContains(t, location, "invalid_request")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			app := GetTestServer(t).App
			data, contentType := tc.ReqFn(t)

			form := make(url.Values)
			form.Add("code", data.Code)
			form.Add("state", data.State)
			form.Add("user", data.User)

			req := httptest.NewRequest(http.MethodPost, appleOAuth2Path, strings.NewReader(form.Encode()))
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			resp, err := app.Test(req)
			if err != nil {
				t.Fatal("Failed to perform request", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Fatal(err)
				}
			}()

			AssertTestStatusCode(t, resp, tc.ExpStatus)
			tc.AssertFn(t, data, resp)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}

func TestOAuthToken(t *testing.T) {
	const oauthTokenPath = "/v1/auth/oauth2/token"
	beforeEachAuthorization := func(t *testing.T) (string, string) {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGitHub))
		testCache := GetTestCache(t)
		testTokens := GetTestTokens(t)
		testServices := GetTestServices(t)
		requestID := uuid.NewString()
		ctx := context.Background()

		code, err := testCache.GenerateOAuthCode(ctx, cache.GenerateOAuthOptions{
			RequestID:       requestID,
			Email:           account.Email,
			DurationSeconds: testTokens.GetOAuthTTL(),
		})
		if err != nil {
			t.Fatal("Failed to generate OAuth code", err)
		}

		accessToken := testTokens.CreateOAuthToken(tokens.AccountOAuthTokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version(),
		})
		if err != nil {
			t.Fatal("Failed to create OAuth token", err)
		}

		sAccessToken, serviceErr := GetTestCrypto(t).SignToken(
			context.Background(),
			crypto.SignTokenOptions{
				RequestID: requestID,
				Token:     accessToken,
				GetJWKfn: testServices.BuildGetGlobalEncryptedJWKFn(ctx, services.BuildEncryptedJWKFnOptions{
					RequestID: requestID,
					KeyType:   database.TokenKeyTypeOauthAuthorization,
					TTL:       testTokens.GetOAuthTTL(),
				}),
				GetDecryptDEKfn: testServices.BuildGetGlobalDecDEKFn(ctx, requestID),
			},
		)
		if serviceErr != nil {
			t.Fatal("Failed to sign access token", serviceErr)
		}

		return code, sAccessToken
	}

	beforeEachRefresh := func(t *testing.T) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
		testTokens := GetTestTokens(t)
		testServices := GetTestServices(t)
		requestID := uuid.NewString()
		ctx := context.Background()

		refreshToken, err := testTokens.CreateRefreshToken(tokens.AccountRefreshTokenOptions{
			PublicID: account.PublicID,
			Version:  account.Version(),
			Scopes:   []tokens.AccountScope{tokens.AccountScopeEmail, tokens.AccountScopeProfile, tokens.AccountScopeAdmin},
		})
		if err != nil {
			t.Fatal("Failed to create refresh token", err)
		}

		sRefreshToken, serviceErr := GetTestCrypto(t).SignToken(ctx, crypto.SignTokenOptions{
			RequestID: requestID,
			Token:     refreshToken,
			GetJWKfn: testServices.BuildGetGlobalEncryptedJWKFn(ctx, services.BuildEncryptedJWKFnOptions{
				RequestID: requestID,
				KeyType:   database.TokenKeyTypeRefresh,
				TTL:       testTokens.GetRefreshTTL(),
			}),
			GetDecryptDEKfn: testServices.BuildGetGlobalDecDEKFn(ctx, requestID),
		})
		if serviceErr != nil {
			t.Fatal("Failed to sign refresh token", serviceErr)
		}

		return sRefreshToken
	}

	beforeEachBearerJWT := func(
		t *testing.T,
		algorithm database.TokenCryptoSuite,
		issuer string,
		expDuration time.Duration,
		iat *time.Time,
		nbf *time.Time,
	) string {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderApple))
		cred, serviceErr := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			Alias:           "update-cred",
			Scopes:          []string{"account:admin"},
			AuthMethods:     "private_key_jwt",
			Issuers:         []string{"https://issuer.example.com"},
			Algorithm:       string(algorithm),
		})
		if serviceErr != nil {
			t.Fatalf("Failed to create account credentials: %v", serviceErr)
		}

		mapTime := func(tm *time.Time) *jwt.NumericDate {
			if tm == nil {
				return nil
			}
			return jwt.NewNumericDate(*tm)
		}

		mapExp := func(ia *time.Time, nb *time.Time) *jwt.NumericDate {
			if ia != nil {
				return jwt.NewNumericDate(ia.Add(expDuration))
			}
			if nb != nil {
				return jwt.NewNumericDate(nb.Add(expDuration))
			}
			return jwt.NewNumericDate(time.Now().Add(expDuration))
		}

		jwk := cred.ClientSecretJWK
		claims := jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   cred.ClientID,
			Audience:  jwt.ClaimStrings{"https://" + GetTestConfig(t).BackendDomain()},
			ExpiresAt: mapExp(iat, nbf),
			NotBefore: mapTime(nbf),
			IssuedAt:  mapTime(iat),
			ID:        uuid.NewString(),
		}
		var signingMethod jwt.SigningMethod
		switch algorithm {
		case database.TokenCryptoSuiteES256:
			signingMethod = jwt.SigningMethodES256
		case database.TokenCryptoSuiteEdDSA:
			signingMethod = jwt.SigningMethodEdDSA
		default:
			t.Fatalf("Unsupported algorithm: %s", algorithm)
		}
		token := jwt.NewWithClaims(signingMethod, claims)
		token.Header["kid"] = jwk.GetKeyID()

		privateKey, err := jwk.ToPrivateKey()
		if err != nil {
			t.Fatalf("Failed to convert JWK to private key: %v", err)
		}

		signedToken, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatalf("Failed to sign token: %v", err)
		}

		return signedToken
	}

	beforeEachClientCredentials := func(t *testing.T, authMethods string) (string, string) {
		var am string
		switch authMethods {
		case "client_secret_basic", "client_secret_post", "both_client_secrets":
			am = authMethods
		default:
			t.Fatalf("Unsupported auth methods: %s", authMethods)
		}

		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderMicrosoft))
		cred, serviceErr := GetTestServices(t).CreateAccountCredentials(context.Background(), services.CreateAccountCredentialsOptions{
			RequestID:       uuid.NewString(),
			AccountPublicID: account.PublicID,
			AccountVersion:  account.Version(),
			Alias:           "update-cred",
			Scopes:          []string{"account:admin"},
			AuthMethods:     am,
			Issuers:         []string{"https://issuer.example.com"},
		})
		if serviceErr != nil {
			t.Fatalf("Failed to create account credentials: %v", serviceErr)
		}

		return cred.ClientID, cred.ClientSecret
	}

	createAuthorizationBody := func(code string) string {
		form := make(url.Values)
		form.Add("code", code)
		form.Add("grant_type", "authorization_code")
		form.Add("redirect_uri", "https://localhost:3000/auth/callback")
		return form.Encode()
	}

	createRefreshBody := func(refreshToken string) string {
		form := make(url.Values)
		form.Add("refresh_token", refreshToken)
		form.Add("grant_type", "refresh_token")
		return form.Encode()
	}

	createBearerJWTBody := func(token string, scope string) string {
		form := make(url.Values)
		form.Add("assertion", token)
		form.Add("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		if scope != "" {
			form.Add("scope", scope)
		}
		return form.Encode()
	}

	createClientCredentialsBodyAndAH := func(
		authMethod string,
		clientID string,
		clientSecret string,
		audience string,
		scope string,
	) (string, string) {
		form := make(url.Values)
		form.Add("grant_type", "client_credentials")

		if audience != "" {
			form.Add("audience", audience)
		}
		if scope != "" {
			form.Add("scope", scope)
		}

		if authMethod == "client_secret_basic" {
			return form.Encode(), base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
		}

		form.Add("client_id", clientID)
		form.Add("client_secret", clientSecret)
		return form.Encode(), ""
	}

	testCases := []TestRequestCase[string]{
		{
			Name: "POST should return 200 OK with authorization_code grant type with valid code and token",
			ReqFn: func(t *testing.T) (string, string) {
				code, accessToken := beforeEachAuthorization(t)
				return createAuthorizationBody(code), accessToken
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[string],
		},
		{
			Name: "POST should return 400 BAD REQUEST invalid_grant with authorization_code grant type with invalid code and valid token",
			ReqFn: func(t *testing.T) (string, string) {
				_, accessToken := beforeEachAuthorization(t)
				return createAuthorizationBody(utils.Base62UUID()), accessToken
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidGrant)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with authorization_code grant type with valid code and invalid token",
			ReqFn: func(t *testing.T) (string, string) {
				code, accessToken := beforeEachAuthorization(t)
				return createAuthorizationBody(code), accessToken + "invalid"
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 200 OK with refresh_token grant type with valid refresh token",
			ReqFn: func(t *testing.T) (string, string) {
				refreshToken := beforeEachRefresh(t)
				return createRefreshBody(refreshToken), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertFullAuthAccessResponse[string],
		},
		{
			Name: "POST should return 400 BAD REQUEST invalid_request with refresh_token grant type with invalid refresh token",
			ReqFn: func(t *testing.T) (string, string) {
				return createRefreshBody("not-a-token"), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidRequest)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with refresh_token grant type with refresh token with invalid claims",
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderGoogle))
				testTokens := GetTestTokens(t)
				requestID := uuid.NewString()

				refreshToken, err := testTokens.CreateRefreshToken(tokens.AccountRefreshTokenOptions{
					PublicID: account.PublicID,
					Version:  account.Version() + 2,
					Scopes:   []tokens.AccountScope{tokens.AccountScopeEmail, tokens.AccountScopeProfile, tokens.AccountScopeAdmin},
				})
				if err != nil {
					t.Fatal("Failed to create refresh token", err)
				}

				sRefreshToken, serviceErr := GetTestCrypto(t).SignToken(
					context.Background(),
					crypto.SignTokenOptions{
						RequestID: requestID,
						Token:     refreshToken,
						GetJWKfn: GetTestServices(t).BuildGetGlobalEncryptedJWKFn(
							context.Background(),
							services.BuildEncryptedJWKFnOptions{
								RequestID: requestID,
								KeyType:   database.TokenKeyTypeRefresh,
								TTL:       testTokens.GetRefreshTTL(),
							},
						),
					},
				)
				if serviceErr != nil {
					t.Fatal("Failed to sign refresh token", serviceErr)
				}

				return createRefreshBody(sRefreshToken), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 200 OK with private_key_jwt grant type with valid ES256 JWT token",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					5*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 200 OK with private_key_jwt grant type with valid EdDSA JWT token",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteEdDSA,
					"https://issuer.example.com",
					5*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 200 OK with private_key_jwt grant type with valid ES256 JWT token with minimal claims",
			ReqFn: func(t *testing.T) (string, string) {
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					5*time.Minute,
					nil,
					nil,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 200 OK with private_key_jwt grant type with valid EdDSA JWT token with only nbf claim",
			ReqFn: func(t *testing.T) (string, string) {
				minusOne := time.Now().Add(-1 * time.Minute)
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteEdDSA,
					"https://issuer.example.com",
					5*time.Minute,
					nil,
					&minusOne,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 200 OK with private_key_jwt grant type with valid ES256 JWT token and valid claims",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					5*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, strings.Join([]string{
					string(database.AccountCredentialsScopeAccountAppsRead),
					string(database.AccountCredentialsScopeAccountUsersRead),
					string(database.AccountCredentialsScopeAccountCredentialsRead),
				}, " ")), ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 401 UNAUTHORIZED unauthorized_client with private_key_jwt grant type with invalid issuer",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://invalid-issuer.example.com",
					5*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorUnauthorizedClient)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with private_key_jwt grant type with an extensive lifespan token",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					10*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with private_key_jwt grant type with an extensive lifespan token with minimal claims",
			ReqFn: func(t *testing.T) (string, string) {
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					10*time.Minute,
					nil,
					nil,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with private_key_jwt grant type with an extensive lifespan token with minimal nbf",
			ReqFn: func(t *testing.T) (string, string) {
				minusOne := time.Now().Add(-1 * time.Minute)
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					10*time.Minute,
					nil,
					&minusOne,
				)
				return createBearerJWTBody(signedToken, ""), ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 400 BAD REQUEST invalid_request with private_key_jwt grant type with invalid JWT token",
			ReqFn: func(t *testing.T) (string, string) {
				return createBearerJWTBody("not-a-jwt", ""), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidRequest)
			},
		},
		{
			Name: "POST should return 400 BAD REQUEST with private_key_jwt grant type with invalid scope",
			ReqFn: func(t *testing.T) (string, string) {
				now := time.Now()
				signedToken := beforeEachBearerJWT(
					t,
					database.TokenCryptoSuiteES256,
					"https://issuer.example.com",
					5*time.Minute,
					&now,
					&now,
				)
				return createBearerJWTBody(signedToken, strings.Join([]string{
					string(database.AccountCredentialsScopeAccountAppsRead),
					"account:unknown:read",
				}, " ")), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidScope)
			},
		},
		{
			Name: "POST should return 200 OK with client_credentials grant type with valid client_id and client_secret, and basic auth",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "client_secret_basic")
				body, authHeader := createClientCredentialsBodyAndAH("client_secret_basic", clientID, clientSecret, "", "")
				return body, authHeader
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
			TokenType: "Basic",
		},
		{
			Name: "POST should return 200 OK with client_credentials grant type with valid client_id and client_secret, and post form",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "client_secret_post")
				body, _ := createClientCredentialsBodyAndAH("client_secret_post", clientID, clientSecret, "", "")
				return body, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 200 OK with client_credentials grant type with valid client_id and client_secret, with both auth methods using basic auth and a valid audience",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "both_client_secrets")
				body, authHeader := createClientCredentialsBodyAndAH(
					"client_secret_basic",
					clientID,
					clientSecret,
					fmt.Sprintf("https://%s", GetTestConfig(t).BackendDomain()),
					"",
				)
				return body, authHeader
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
			TokenType: "Basic",
		},
		{
			Name: "POST should return 200 OK with client_credentials grant type with valid client_id and client_secret, with both auth methods using post auth and a valid scope",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "both_client_secrets")
				body, _ := createClientCredentialsBodyAndAH(
					"client_secret_post",
					clientID,
					clientSecret,
					"",
					"account:users:read account:admin",
				)
				return body, ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  assertAuthAccessResponse[string],
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with client_credentials grant type with invalid client_id and client_secret",
			ReqFn: func(t *testing.T) (string, string) {
				body, _ := createClientCredentialsBodyAndAH("client_secret_post", "invalid-client-id", "invalid-client-secret", "", "")
				return body, ""
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
		},
		{
			Name: "POST should return 400 BAD REQUEST invalid_request with client_credentials grant type with missing client_secret",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, _ := beforeEachClientCredentials(t, "client_secret_post")
				body, _ := createClientCredentialsBodyAndAH("client_secret_post", clientID, "", "", "")
				return body, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidRequest)
			},
		},
		{
			Name: "POST should return 401 UNAUTHORIZED access_denied with client_credentials grant type with invalid audience",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "client_secret_basic")
				body, token := createClientCredentialsBodyAndAH(
					"client_secret_basic",
					clientID,
					clientSecret,
					"https://invalid-audience.example.com",
					"",
				)
				return body, token
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorAccessDenied)
			},
			TokenType: "Basic",
		},
		{
			Name: "POST should return 400 BAD REQUEST invalid_scope with client_credentials grant type with invalid scope",
			ReqFn: func(t *testing.T) (string, string) {
				clientID, clientSecret := beforeEachClientCredentials(t, "client_secret_post")
				body, _ := createClientCredentialsBodyAndAH(
					"client_secret_post",
					clientID,
					clientSecret,
					"",
					"account:unknown:read",
				)
				return body, ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn: func(t *testing.T, req string, res *http.Response) {
				resBody := AssertTestResponseBody(t, res, exceptions.OAuthErrorResponse{})
				AssertEqual(t, resBody.Error, exceptions.OAuthErrorInvalidScope)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCaseWihURLEncodedBody(t, http.MethodPost, oauthTokenPath, tc)
		})
	}

	t.Cleanup(accountsCleanUp(t))
}
