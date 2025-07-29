// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	"github.com/go-faker/faker/v4"
	"github.com/gofiber/fiber/v2"
	fiberRedis "github.com/gofiber/storage/redis/v3"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	openbao "github.com/openbao/openbao/api/v2"
	"github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/server"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const v1Path string = "/v1"

var _testConfig *config.Config
var _testServices *services.Services
var _testServer *server.FiberServer
var _testTokens *tokens.Tokens
var _testDatabase *database.Database
var _testCache *cache.Cache
var _testCrypto *crypto.Crypto

func initTestServicesAndApp(t *testing.T) {
	logger := server.DefaultLogger()
	cfg := config.NewConfig(logger, "../.env")
	logger = server.ConfigLogger(cfg.LoggerConfig())
	_testConfig = &cfg
	ctx := context.Background()

	logger.InfoContext(ctx, "Building distributed cache...")
	cacheStorage := fiberRedis.New(fiberRedis.Config{
		URL: _testConfig.RedisURL(),
	})

	dcCfg := _testConfig.DistributedCache()
	_testCache = cache.NewCache(
		logger,
		cacheStorage,
		dcCfg.KEKTTL(),
		dcCfg.DEKDecTTL(),
		dcCfg.DEKEncTTL(),
		dcCfg.PublicJWKTTL(),
		dcCfg.PrivateJWKTTL(),
		dcCfg.PublicJWKsTTL(),
		dcCfg.AccountUsernameTTL(),
		dcCfg.WellKnownOIDCConfigTTL(),
	)
	logger.InfoContext(ctx, "Finished building distributed cache")

	// Build database connection
	logger.InfoContext(ctx, "Building database connection...")
	pgCfg, err := pgxpool.ParseConfig(_testConfig.DatabaseURL())
	if err != nil {
		t.Fatal("Failed to parse database URL", err)
	}
	pgCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		logger.InfoContext(ctx, "Loading types into database connection pool...")

		ts, err := conn.LoadTypes(ctx, server.PgTypes[:])
		if err != nil {
			logger.ErrorContext(ctx, "Failed to load normal types into database connection pool", "error", err)
			return err
		}
		conn.TypeMap().RegisterTypes(ts)

		arrTypes := utils.MapSlice(server.PgTypes[:], func(t *string) string {
			return "_" + *t
		})
		ts, err = conn.LoadTypes(ctx, arrTypes)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to load prefixed types into database connection pool", "error", err)
			return err
		}
		conn.TypeMap().RegisterTypes(ts)

		logger.InfoContext(ctx, "Types loaded into database connection pool")
		return nil
	}
	dbConnPool, err := pgxpool.NewWithConfig(ctx, pgCfg)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to connect to database", "error", err)
		t.Fatal("Failed to connect to database", err)
	}
	_testDatabase = database.NewDatabase(dbConnPool)
	logger.InfoContext(ctx, "Finished building database connection")

	logger.InfoContext(ctx, "Building mailer...")
	redisCfg, err := redis.ParseURL(_testConfig.RedisURL())
	if err != nil {
		logger.ErrorContext(ctx, "Failed to parse redis url", "error", err)
		t.Fatal("Failed to parse redis url", err)
	}
	mail := mailer.NewEmailPublisher(
		redis.NewClient(redisCfg),
		_testConfig.EmailPubChannel(),
		_testConfig.FrontendDomain(),
		logger,
	)
	logger.InfoContext(ctx, "Finished building mailer")

	logger.InfoContext(ctx, "Building JWT token keys...")
	tokensCfg := _testConfig.TokensConfig()
	_testTokens = tokens.NewTokens(
		logger,
		cfg.BackendDomain(),
		tokensCfg.AccessTTL(),
		tokensCfg.AccountCredentialsTTL(),
		tokensCfg.AppsTTL(),
		tokensCfg.RefreshTTL(),
		tokensCfg.ConfirmTTL(),
		tokensCfg.ResetTTL(),
		tokensCfg.OAuthTTL(),
		tokensCfg.TwoFATTL(),
	)
	logger.InfoContext(ctx, "Finished building JWT tokens keys")

	logger.InfoContext(ctx, "Building crypto...")
	cryptCfg := cfg.CryptoConfig()

	logger.InfoContext(ctx, "Building OpenBao client...")
	obCfg := cfg.OpenBaoConfig()
	obc := openbao.DefaultConfig()
	obc.Address = obCfg.URLAddress()
	obClient, err := openbao.NewClient(obc)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to initialize OpenBao client", "error", err)
		t.Fatal("Failed to initialize OpenBao client", err)
	}

	obClient.SetToken(obCfg.DevToken())
	mount, err := obClient.Sys().MountInfo(cryptCfg.KEKPath() + "/")
	if err != nil {
		if err = obClient.Sys().Mount(cryptCfg.KEKPath(), &openbao.MountInput{
			Type: "transit",
		}); err != nil {
			logger.ErrorContext(ctx, "Failed to mount KEK path in OpenBao", "error", err)
			t.Fatal("Failed to mount KEK path in OpenBao", err)
		}
	} else {
		logger.InfoContext(ctx, "KEK path already mounted in OpenBao", "mountID", mount.UUID, "type", mount.Type)
	}

	logger.InfoContext(ctx, "Building local cache...")
	localCacheCfg := cfg.LocalCacheConfig()
	localCache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters:            localCacheCfg.Counter(),
		MaxCost:                localCacheCfg.MaxCost(),
		BufferItems:            localCacheCfg.BufferItems(),
		TtlTickerDurationInSec: localCacheCfg.DefaultTTL(),
	})
	if err != nil {
		logger.ErrorContext(ctx, "Failed to initialize local cache", "error", err)
		t.Fatal("Failed to initialize local cache", err)
	}
	logger.InfoContext(ctx, "Finished building local cache")

	_testCrypto = crypto.NewCrypto(
		logger,
		obClient,
		localCache,
		cfg.ServiceName(),
		cryptCfg,
	)
	logger.InfoContext(ctx, "Finished building crypto")

	logger.InfoContext(ctx, "Building OAuth provider...")
	oauthProvidersCfg := _testConfig.OAuthProvidersConfig()
	oauthProviders := oauth.NewProviders(
		logger,
		oauthProvidersCfg.GitHub(),
		oauthProvidersCfg.Google(),
		oauthProvidersCfg.Facebook(),
		oauthProvidersCfg.Apple(),
		oauthProvidersCfg.Microsoft(),
	)
	logger.InfoContext(ctx, "Finished building OAuth provider")

	_testServices = services.NewServices(
		logger,
		_testDatabase,
		_testCache,
		mail,
		_testTokens,
		_testCrypto,
		oauthProviders,
		cfg.KEKExpirationDays(),
		cfg.DEKExpirationDays(),
		cfg.JWKExpirationDays(),
		cfg.AccountCCExpDays(),
		cfg.UserCCExpDays(),
	)

	_testServer = server.New(ctx, logger, *_testConfig)
}

func GetTestConfig(t *testing.T) *config.Config {
	if _testConfig == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testConfig
}

func GetTestServices(t *testing.T) *services.Services {
	if _testServices == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testServices
}

func GetTestDatabase(t *testing.T) *database.Database {
	if _testDatabase == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testDatabase
}

func GetTestCache(t *testing.T) *cache.Cache {
	if _testCache == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testCache
}

func GetTestServer(t *testing.T) *server.FiberServer {
	if _testServer == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testServer
}

func GetTestTokens(t *testing.T) *tokens.Tokens {
	if _testTokens == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testTokens
}

func GetTestCrypto(t *testing.T) *crypto.Crypto {
	if _testCrypto == nil {
		initTestServicesAndApp(t)
		_testServer.RegisterFiberRoutes()
	}

	return _testCrypto
}

func CreateTestJSONRequestBody(t *testing.T, reqBody any) *bytes.Reader {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal("Failed to marshal JSON", err)
	}

	return bytes.NewReader(jsonBody)
}

func PerformTestRequest(t *testing.T, app *fiber.App, delayMs int, method, path, tokenType, accessToken, contentType string, body io.Reader) *http.Response {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	if accessToken != "" {
		req.Header.Set("Authorization", tokenType+" "+accessToken)
	}

	resp, err := app.Test(req, 2000)
	if err != nil {
		t.Fatal("Failed to perform request", err)
	}

	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	return resp
}

func PerformTestRequestWithURLEncodedBody(t *testing.T, app *fiber.App, delayMs int, method, path, tokenType, accessToken, body string) *http.Response {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if accessToken != "" {
		req.Header.Set("Authorization", tokenType+" "+accessToken)
	}

	resp, err := app.Test(req, 60000)
	if err != nil {
		t.Fatal("Failed to perform request", err)
	}

	if delayMs > 0 {
		time.Sleep(time.Duration(delayMs) * time.Millisecond)
	}

	return resp
}

func AssertTestStatusCode(t *testing.T, resp *http.Response, expectedStatusCode int) {
	if resp.StatusCode != expectedStatusCode {
		t.Logf("Status Code: %d", resp.StatusCode)
		t.Fatal("Failed to assert status code")
	}
}

func AssertTestResponseBody[V interface{}](t *testing.T, resp *http.Response, expectedBody V) V {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal("Failed to read response body", err)
	}

	if err := json.Unmarshal(body, &expectedBody); err != nil {
		t.Logf("Body: %s", body)
		t.Fatal("Failed to unmarshal response body", err)
	}
	return expectedBody
}

func AssertEqual[V comparable](t *testing.T, actual, expected V) {
	if expected != actual {
		t.Fatalf("Actual: %v, Expected: %v", actual, expected)
	}
}

func AssertNotEmpty[V comparable](t *testing.T, actual V) {
	var empty V
	if actual == empty {
		t.Fatal("Value is empty")
	}
}

func AssertEmpty[V comparable](t *testing.T, actual V) {
	var empty V
	if actual != empty {
		t.Fatal("Value is not empty")
	}
}

func AssertStringContains(t *testing.T, actual string, expected string) {
	if !strings.Contains(actual, expected) {
		t.Fatalf("Actual: %s, Expected: %s", actual, expected)
	}
}

type TestRequestCase[R any] struct {
	Name      string
	ReqFn     func(t *testing.T) (R, string)
	ExpStatus int
	AssertFn  func(t *testing.T, req R, res *http.Response)
	DelayMs   int
	Path      string
	PathFn    func() string
	Method    string
	TokenType string
}

func PerformTestRequestCase[R any](t *testing.T, method, path string, tc TestRequestCase[R]) {
	// Arrange
	reqBody, accessToken := tc.ReqFn(t)
	jsonBody := CreateTestJSONRequestBody(t, reqBody)
	fiberApp := GetTestServer(t).App
	tokenType := "Bearer"
	if tc.TokenType != "" {
		tokenType = tc.TokenType
	}

	// Act
	resp := PerformTestRequest(t, fiberApp, tc.DelayMs, method, path, tokenType, accessToken, "application/json", jsonBody)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Assert
	AssertTestStatusCode(t, resp, tc.ExpStatus)
	tc.AssertFn(t, reqBody, resp)
}

func PerformTestRequestCaseWihURLEncodedBody(t *testing.T, method, path string, tc TestRequestCase[string]) {
	// Arrange
	reqBody, accessToken := tc.ReqFn(t)
	fiberApp := GetTestServer(t).App
	tokenType := "Bearer"
	if tc.TokenType != "" {
		tokenType = tc.TokenType
	}

	// Act
	resp := PerformTestRequestWithURLEncodedBody(t, fiberApp, tc.DelayMs, method, path, tokenType, accessToken, reqBody)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Assert
	AssertTestStatusCode(t, resp, tc.ExpStatus)
	tc.AssertFn(t, reqBody, resp)
}

func PerformTestRequestCaseWithPathFn[R any](t *testing.T, method string, tc TestRequestCase[R]) {
	// Arrange
	reqBody, accessToken := tc.ReqFn(t)
	jsonBody := CreateTestJSONRequestBody(t, reqBody)
	fiberApp := GetTestServer(t).App
	tokenType := "Bearer"
	if tc.TokenType != "" {
		tokenType = tc.TokenType
	}

	// Act
	path := tc.PathFn()
	resp := PerformTestRequest(t, fiberApp, tc.DelayMs, method, path, tokenType, accessToken, "application/json", jsonBody)
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	// Assert
	AssertTestStatusCode(t, resp, tc.ExpStatus)
	tc.AssertFn(t, reqBody, resp)
}

type fakeAccountData struct {
	Email     string `faker:"email"`
	FirstName string `faker:"first_name"`
	LastName  string `faker:"last_name"`
	Password  string `faker:"oneof: Pas@w0rd123, P@sW0rd456, P@ssw0rd789, P@ssW0rd012, P@ssw0rd!345"`
}

func GenerateFakeAccountData(t *testing.T, provider string) services.CreateAccountOptions {
	fakeData := fakeAccountData{}
	if err := faker.FakeData(&fakeData); err != nil {
		t.Fatal("Failed to generate fake data", err)
	}

	return services.CreateAccountOptions{
		RequestID:  uuid.NewString(),
		Email:      fakeData.Email,
		GivenName:  fakeData.FirstName,
		FamilyName: fakeData.LastName,
		Provider:   provider,
		Password:   fakeData.Password,
	}
}

func CreateTestAccount(t *testing.T, userData services.CreateAccountOptions) dtos.AccountDTO {
	serv := GetTestServices(t)
	ctx := context.Background()

	account, err := serv.CreateAccount(ctx, userData)
	if err != nil {
		t.Fatal("Failed to create account", err)
	}

	return account
}

func GenerateTestAccountAuthTokens(t *testing.T, account *dtos.AccountDTO) (string, string) {
	tks := GetTestTokens(t)
	cpt := GetTestCrypto(t)
	s := GetTestServices(t)
	requestID := uuid.NewString()
	ctx := context.Background()

	accessToken, err := tks.CreateAccessToken(tokens.AccountAccessTokenOptions{
		PublicID:     account.PublicID,
		Version:      account.Version(),
		TokenSubject: account.PublicID.String(),
		Scopes:       []tokens.AccountScope{tokens.AccountScopeAdmin},
	})
	if err != nil {
		t.Fatal("Failed to create access token", err)
	}

	sAccessToken, serviceErr := cpt.SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     accessToken,
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(
			ctx,
			services.BuildEncryptedJWKFnOptions{
				RequestID: requestID,
				KeyType:   database.TokenKeyTypeAccess,
				TTL:       tks.GetAccessTTL(),
			},
		),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, requestID),
	})
	if serviceErr != nil {
		t.Fatal("Failed to sign access token", serviceErr)
	}

	refreshToken, err := tks.CreateRefreshToken(tokens.AccountRefreshTokenOptions{
		PublicID: account.PublicID,
		Version:  account.Version(),
		Scopes:   []tokens.AccountScope{tokens.AccountScopeAdmin},
	})
	if err != nil {
		t.Fatal("Failed to create refresh token", err)
	}

	sRefreshToken, serviceErr := cpt.SignToken(
		ctx,
		crypto.SignTokenOptions{
			RequestID: requestID,
			Token:     refreshToken,
			GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(
				ctx,
				services.BuildEncryptedJWKFnOptions{
					RequestID: requestID,
					KeyType:   database.TokenKeyTypeRefresh,
					TTL:       tks.GetRefreshTTL(),
				},
			),
			GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, requestID),
		},
	)
	if serviceErr != nil {
		t.Fatal("Failed to sign refresh token", serviceErr)
	}

	return sAccessToken, sRefreshToken
}

func GenerateScopedAccountAccessToken(t *testing.T, account *dtos.AccountDTO, scopes []tokens.AccountScope) string {
	tks := GetTestTokens(t)
	s := GetTestServices(t)
	requestID := uuid.NewString()
	ctx := context.Background()

	accessToken, err := tks.CreateAccessToken(tokens.AccountAccessTokenOptions{
		PublicID:     account.PublicID,
		Version:      account.Version(),
		TokenSubject: account.PublicID.String(),
		Scopes:       scopes,
	})
	if err != nil {
		t.Fatal("Failed to create access token", err)
	}

	sAccessToken, serviceErr := GetTestCrypto(t).SignToken(ctx, crypto.SignTokenOptions{
		RequestID: requestID,
		Token:     accessToken,
		GetJWKfn: s.BuildGetGlobalEncryptedJWKFn(
			ctx,
			services.BuildEncryptedJWKFnOptions{
				RequestID: requestID,
				KeyType:   database.TokenKeyTypeAccess,
				TTL:       tks.GetAccessTTL(),
			},
		),
		GetDecryptDEKfn: s.BuildGetGlobalDecDEKFn(ctx, requestID),
	})
	if serviceErr != nil {
		t.Fatal("Failed to sign access token", serviceErr)
	}

	return sAccessToken
}

func assertErrorResponse(t *testing.T, res *http.Response, code, message string) {
	resBody := AssertTestResponseBody(t, res, exceptions.ErrorResponse{})
	AssertEqual(t, message, resBody.Message)
	AssertEqual(t, code, resBody.Code)
}

func AssertUnauthorizedError[T any](t *testing.T, _ T, res *http.Response) {
	assertErrorResponse(t, res, exceptions.StatusUnauthorized, exceptions.MessageUnauthorized)
}

func AssertForbiddenError[T any](t *testing.T, _ T, res *http.Response) {
	assertErrorResponse(t, res, exceptions.StatusForbidden, exceptions.MessageForbidden)
}

func AssertNotFoundError[T any](t *testing.T, _ T, res *http.Response) {
	assertErrorResponse(t, res, exceptions.StatusNotFound, exceptions.MessageNotFound)
}
