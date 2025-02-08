package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/go-faker/faker/v4"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	fiberRedis "github.com/gofiber/storage/redis/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/providers/vault"
	"github.com/tugascript/devlogs/idp/internal/server"
	"github.com/tugascript/devlogs/idp/internal/services"
)

var _testConfig *config.Config
var _testServices *services.Services
var _testServer *server.FiberServer
var _testTokens *tokens.Tokens
var _testDatabase *database.Database
var _testCache *cache.Cache

func initTestServicesAndApp(t *testing.T) {
	logger := server.DefaultLogger()
	cfg := config.NewConfig(logger, "../.env")
	_testConfig = &cfg
	ctx := context.Background()

	logger.InfoContext(ctx, "Building redis storage...")
	cacheStorage := fiberRedis.New(fiberRedis.Config{
		URL: _testConfig.RedisURL(),
	})
	_testCache = cache.NewCache(
		logger,
		cacheStorage,
	)
	logger.InfoContext(ctx, "Finished building redis storage")

	// Build database connection
	logger.InfoContext(ctx, "Building database connection...")
	dbConnPool, err := pgxpool.New(ctx, _testConfig.DatabaseURL())
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
		panic(err)
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
		tokensCfg.Access(),
		tokensCfg.AccountCredentials(),
		tokensCfg.Refresh(),
		tokensCfg.Confirm(),
		tokensCfg.Reset(),
		tokensCfg.OAuth(),
		tokensCfg.TwoFA(),
		_testConfig.FrontendDomain(),
		_testConfig.BackendDomain(),
	)
	logger.InfoContext(ctx, "Finished building JWT tokens keys")

	logger.InfoContext(ctx, "Building vault...")
	vaultStg := vault.NewVault(ctx, logger, _testConfig.VaultConfig())
	logger.InfoContext(ctx, "Finished building vault")

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
		vaultStg,
		oauthProviders,
	)

	_testServer = server.New(ctx, logger, *_testConfig)
}

func GetTestConfig(t *testing.T) *config.Config {
	if _testConfig == nil {
		initTestServicesAndApp(t)
	}

	return _testConfig
}

func GetTestServices(t *testing.T) *services.Services {
	if _testServices == nil {
		initTestServicesAndApp(t)
	}

	return _testServices
}

func GetTestDatabase(t *testing.T) *database.Database {
	if _testDatabase == nil {
		initTestServicesAndApp(t)
	}

	return _testDatabase
}

func GetTestCache(t *testing.T) *cache.Cache {
	if _testCache == nil {
		initTestServicesAndApp(t)
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

func CreateTestJSONRequestBody(t *testing.T, reqBody interface{}) *bytes.Reader {
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatal("Failed to marshal JSON", err)
	}

	return bytes.NewReader(jsonBody)
}

func PerformTestRequest(t *testing.T, app *fiber.App, delayMs int, method, path, accessToken, contentType string, body io.Reader) *http.Response {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
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
		t.Fatal("Failed to register user")
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

type TestRequestCase[R any] struct {
	Name      string
	ReqFn     func(t *testing.T) (R, string)
	ExpStatus int
	AssertFn  func(t *testing.T, req R, res *http.Response)
	DelayMs   int
	Path      string
	PathFn    func() string
	Method    string
}

func PerformTestRequestCase[R any](t *testing.T, method, path string, tc TestRequestCase[R]) {
	// Arrange
	reqBody, accessToken := tc.ReqFn(t)
	jsonBody := CreateTestJSONRequestBody(t, reqBody)
	fiberApp := GetTestServer(t).App

	// Act
	resp := PerformTestRequest(t, fiberApp, tc.DelayMs, method, path, accessToken, "application/json", jsonBody)
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

func GenerateFakeAccountData(t *testing.T) services.CreateAccountOptions {
	fakeData := fakeAccountData{}
	if err := faker.FakeData(&fakeData); err != nil {
		t.Fatal("Failed to generate fake data", err)
	}

	return services.CreateAccountOptions{
		RequestID: uuid.NewString(),
		Email:     fakeData.Email,
		FirstName: fakeData.FirstName,
		LastName:  fakeData.LastName,
		Provider:  services.AuthProviderGoogle,
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
