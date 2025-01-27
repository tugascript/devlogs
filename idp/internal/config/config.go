package config

import (
	"log/slog"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
)

type Config struct {
	port                 int64
	maxProcs             int64
	databaseURL          string
	redisURL             string
	frontendDomain       string
	backendDomain        string
	cookieSecret         string
	cookieName           string
	emailPubChannel      string
	serviceID            uuid.UUID
	loggerConfig         LoggerConfig
	vaultConfig          VaultConfig
	tokensConfig         TokensConfig
	oAuthProvidersConfig OAuthProvidersConfig
	rateLimiterConfig    RateLimiterConfig
}

func (c *Config) Port() int64 {
	return c.port
}

func (c *Config) MaxProcs() int64 {
	return c.maxProcs
}

func (c *Config) DatabaseURL() string {
	return c.databaseURL
}

func (c *Config) RedisURL() string {
	return c.redisURL
}

func (c *Config) FrontendDomain() string {
	return c.frontendDomain
}

func (c *Config) BackendDomain() string {
	return c.backendDomain
}

func (c *Config) CookieSecret() string {
	return c.cookieSecret
}

func (c *Config) CookieName() string {
	return c.cookieName
}

func (c *Config) EmailPubChannel() string {
	return c.emailPubChannel
}

func (c *Config) ServiceID() uuid.UUID {
	return c.serviceID
}

func (c *Config) LoggerConfig() LoggerConfig {
	return c.loggerConfig
}

func (c *Config) VaultConfig() VaultConfig {
	return c.vaultConfig
}

func (c *Config) TokensConfig() TokensConfig {
	return c.tokensConfig
}

func (c *Config) OAuthProvidersConfig() OAuthProvidersConfig {
	return c.oAuthProvidersConfig
}

func (c *Config) RateLimiterConfig() RateLimiterConfig {
	return c.rateLimiterConfig
}

var variables = [63]string{
	"PORT",
	"ENV",
	"DEBUG",
	"SERVICE_NAME",
	"SERVICE_ID",
	"MAX_PROCS",
	"DATABASE_URL",
	"REDIS_URL",
	"FRONTEND_DOMAIN",
	"BACKEND_DOMAIN",
	"COOKIE_SECRET",
	"COOKIE_NAME",
	"INFISICAL_URL",
	"INFISICAL_CLIENT_ID",
	"INFISICAL_CLIENT_SECRET",
	"FRONTEND_DOMAIN",
	"COOKIE_SECRET",
	"REFRESH_COOKIE_NAME",
	"EMAIL_PUB_CHANNEL",
	"JWT_ACCESS_PUBLIC_KEY",
	"JWT_ACCESS_PRIVATE_KEY",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCESS_KID",
	"JWT_ACCOUNT_KEYS_PUBLIC_KEY",
	"JWT_ACCOUNT_KEYS_PRIVATE_KEY",
	"JWT_ACCOUNT_KEYS_TTL_SEC",
	"JWT_ACCOUNT_KEYS_KID",
	"JWT_REFRESH_PUBLIC_KEY",
	"JWT_REFRESH_PRIVATE_KEY",
	"JWT_REFRESH_TTL_SEC",
	"JWT_REFRESH_KID",
	"JWT_CONFIRM_PUBLIC_KEY",
	"JWT_CONFIRM_PRIVATE_KEY",
	"JWT_CONFIRM_TTL_SEC",
	"JWT_CONFIRM_KID",
	"JWT_RESET_PUBLIC_KEY",
	"JWT_RESET_PRIVATE_KEY",
	"JWT_RESET_TTL_SEC",
	"JWT_RESET_KID",
	"JWT_OAUTH_PUBLIC_KEY",
	"JWT_OAUTH_PRIVATE_KEY",
	"JWT_OAUTH_TTL_SEC",
	"JWT_OAUTH_KID",
	"JWT_2FA_PUBLIC_KEY",
	"JWT_2FA_PRIVATE_KEY",
	"JWT_2FA_TTL_SEC",
	"JWT_2FA_KID",
	"JWT_APP_PUBLIC_KEY",
	"JWT_APP_PRIVATE_KEY",
	"JWT_APP_TTL_SEC",
	"JWT_APP_KID",
	"GITHUB_CLIENT_ID",
	"GITHUB_CLIENT_SECRET",
	"GOOGLE_CLIENT_ID",
	"GOOGLE_CLIENT_SECRET",
	"FACEBOOK_CLIENT_ID",
	"FACEBOOK_CLIENT_SECRET",
	"APPLE_CLIENT_ID",
	"APPLE_CLIENT_SECRET",
	"MICROSOFT_CLIENT_ID",
	"MICROSOFT_CLIENT_SECRET",
	"RATE_LIMITER_MAX",
	"RATE_LIMITER_EXP_SEC",
}

var numerics = [11]string{
	"PORT",
	"MAX_PROCS",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCOUNT_KEYS_TTL_SEC",
	"JWT_REFRESH_TTL_SEC",
	"JWT_EMAIL_TTL_SEC",
	"JWT_OAUTH_TTL_SEC",
	"JWT_2FA_TTL_SEC",
	"JWT_APP_TTL_SEC",
	"RATE_LIMITER_MAX",
	"RATE_LIMITER_EXP_SEC",
}

func NewConfig(logger *slog.Logger, envPath string) Config {
	err := godotenv.Load(envPath)
	if err != nil {
		logger.Error("Error loading .env file")
	}

	variablesMap := make(map[string]string)
	for _, variable := range variables {
		value := os.Getenv(variable)
		if value == "" {
			logger.Error(variable + " is not set")
			panic(variable + " is not set")
		}
		variablesMap[variable] = value
	}

	intMap := make(map[string]int64)
	for _, numeric := range numerics {
		value, err := strconv.ParseInt(variablesMap[numeric], 10, 0)
		if err != nil {
			logger.Error(numeric + " is not an integer")
			panic(numeric + " is not an integer")
		}
		intMap[numeric] = value
	}

	env := variablesMap["ENV"]
	return Config{
		port:            intMap["PORT"],
		maxProcs:        intMap["MAX_PROCS"],
		databaseURL:     variablesMap["DATABASE_URL"],
		redisURL:        variablesMap["REDIS_URL"],
		frontendDomain:  variablesMap["FRONTEND_DOMAIN"],
		backendDomain:   variablesMap["BACKEND_DOMAIN"],
		cookieSecret:    variablesMap["COOKIE_SECRET"],
		cookieName:      variablesMap["COOKIE_NAME"],
		emailPubChannel: variablesMap["EMAIL_PUB_CHANNEL"],
		serviceID:       uuid.MustParse(variablesMap["SERVICE_ID"]),
		loggerConfig: NewLoggerConfig(
			strings.ToLower(variablesMap["DEBUG"]) == "true",
			env,
			variablesMap["SERVICE_NAME"],
		),
		vaultConfig: NewVaultConfig(
			variablesMap["INFISICAL_URL"],
			variablesMap["INFISICAL_CLIENT_ID"],
			variablesMap["INFISICAL_CLIENT_SECRET"],
			env,
		),
		tokensConfig: NewTokensConfig(
			NewSingleJwtConfig(
				variablesMap["JWT_ACCESS_PUBLIC_KEY"],
				variablesMap["JWT_ACCESS_PRIVATE_KEY"],
				variablesMap["JWT_ACCESS_KID"],
				intMap["JWT_ACCESS_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_ACCOUNT_KEYS_PUBLIC_KEY"],
				variablesMap["JWT_ACCOUNT_KEYS_PRIVATE_KEY"],
				variablesMap["JWT_ACCOUNT_KEYS_KID"],
				intMap["JWT_ACCOUNT_KEYS_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_REFRESH_PUBLIC_KEY"],
				variablesMap["JWT_REFRESH_PRIVATE_KEY"],
				variablesMap["JWT_REFRESH_KID"],
				intMap["JWT_REFRESH_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_EMAIL_PUBLIC_KEY"],
				variablesMap["JWT_EMAIL_PRIVATE_KEY"],
				variablesMap["JWT_EMAIL_KID"],
				intMap["JWT_EMAIL_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_OAUTH_PUBLIC_KEY"],
				variablesMap["JWT_OAUTH_PRIVATE_KEY"],
				variablesMap["JWT_OAUTH_KID"],
				intMap["JWT_OAUTH_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_2FA_PUBLIC_KEY"],
				variablesMap["JWT_2FA_PRIVATE_KEY"],
				variablesMap["JWT_2FA_KID"],
				intMap["JWT_2FA_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_APP_PUBLIC_KEY"],
				variablesMap["JWT_APP_PRIVATE_KEY"],
				variablesMap["JWT_APP_KID"],
				intMap["JWT_APP_TTL_SEC"],
			),
		),
		oAuthProvidersConfig: NewOAuthProviders(
			NewOAuthProvider(variablesMap["GITHUB_CLIENT_ID"], variablesMap["GITHUB_CLIENT_SECRET"]),
			NewOAuthProvider(variablesMap["GOOGLE_CLIENT_ID"], variablesMap["GOOGLE_CLIENT_SECRET"]),
			NewOAuthProvider(variablesMap["FACEBOOK_CLIENT_ID"], variablesMap["FACEBOOK_CLIENT_SECRET"]),
			NewOAuthProvider(variablesMap["APPLE_CLIENT_ID"], variablesMap["APPLE_CLIENT_SECRET"]),
			NewOAuthProvider(variablesMap["MICROSOFT_CLIENT_ID"], variablesMap["MICROSOFT_CLIENT_SECRET"]),
		),
		rateLimiterConfig: NewRateLimiterConfig(
			intMap["RATE_LIMITER_MAX"],
			intMap["RATE_LIMITER_EXP_SEC"],
		),
	}
}
