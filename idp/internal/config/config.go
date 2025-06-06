// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	accountUsernameTTL   int64
	frontendDomain       string
	backendDomain        string
	cookieSecret         string
	cookieName           string
	emailPubChannel      string
	encryptionSecret     string
	serviceID            uuid.UUID
	loggerConfig         LoggerConfig
	tokensConfig         TokensConfig
	oAuthProvidersConfig OAuthProvidersConfig
	rateLimiterConfig    RateLimiterConfig
	encryptionConfig     EncryptionConfig
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

func (c *Config) AccountUsernameTTL() int64 {
	return c.accountUsernameTTL
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

func (c *Config) EncryptionSecret() string {
	return c.encryptionSecret
}

func (c *Config) ServiceID() uuid.UUID {
	return c.serviceID
}

func (c *Config) LoggerConfig() LoggerConfig {
	return c.loggerConfig
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

func (c *Config) EncryptionConfig() EncryptionConfig {
	return c.encryptionConfig
}

var variables = [44]string{
	"PORT",
	"ENV",
	"DEBUG",
	"SERVICE_NAME",
	"SERVICE_ID",
	"MAX_PROCS",
	"DATABASE_URL",
	"REDIS_URL",
	"ACCOUNT_USERNAME_TTL",
	"FRONTEND_DOMAIN",
	"BACKEND_DOMAIN",
	"COOKIE_SECRET",
	"COOKIE_NAME",
	"RATE_LIMITER_MAX",
	"RATE_LIMITER_EXP_SEC",
	"EMAIL_PUB_CHANNEL",
	"JWT_ACCESS_PUBLIC_KEY",
	"JWT_ACCESS_PRIVATE_KEY",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCOUNT_CREDENTIALS_PUBLIC_KEY",
	"JWT_ACCOUNT_CREDENTIALS_PRIVATE_KEY",
	"JWT_ACCOUNT_CREDENTIALS_TTL_SEC",
	"JWT_REFRESH_PUBLIC_KEY",
	"JWT_REFRESH_PRIVATE_KEY",
	"JWT_REFRESH_TTL_SEC",
	"JWT_CONFIRM_PUBLIC_KEY",
	"JWT_CONFIRM_PRIVATE_KEY",
	"JWT_CONFIRM_TTL_SEC",
	"JWT_RESET_PUBLIC_KEY",
	"JWT_RESET_PRIVATE_KEY",
	"JWT_RESET_TTL_SEC",
	"JWT_OAUTH_PUBLIC_KEY",
	"JWT_OAUTH_PRIVATE_KEY",
	"JWT_OAUTH_TTL_SEC",
	"JWT_2FA_PUBLIC_KEY",
	"JWT_2FA_PRIVATE_KEY",
	"JWT_2FA_TTL_SEC",
	"JWT_APPS_PUBLIC_KEY",
	"JWT_APPS_PRIVATE_KEY",
	"JWT_APPS_TTL_SEC",
	"ACCOUNT_SECRET",
	"OIDC_SECRET",
	"USER_SECRET",
	"OLD_SECRETS",
}

var optionalVariables = [18]string{
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
	"OLD_JWT_ACCESS_PUBLIC_KEY",
	"OLD_JWT_ACCOUNT_CREDENTIALS_PUBLIC_KEY",
	"OLD_JWT_REFRESH_PUBLIC_KEY",
	"OLD_JWT_CONFIRM_PUBLIC_KEY",
	"OLD_JWT_RESET_PUBLIC_KEY",
	"OLD_JWT_OAUTH_PUBLIC_KEY",
	"OLD_JWT_2FA_PUBLIC_KEY",
	"OLD_JWT_APPS_PUBLIC_KEY",
}

var numerics = [13]string{
	"PORT",
	"MAX_PROCS",
	"ACCOUNT_USERNAME_TTL",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCOUNT_CREDENTIALS_TTL_SEC",
	"JWT_REFRESH_TTL_SEC",
	"JWT_CONFIRM_TTL_SEC",
	"JWT_RESET_TTL_SEC",
	"JWT_OAUTH_TTL_SEC",
	"JWT_2FA_TTL_SEC",
	"JWT_APPS_TTL_SEC",
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

	for _, variable := range optionalVariables {
		value := os.Getenv(variable)
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
		port:               intMap["PORT"],
		maxProcs:           intMap["MAX_PROCS"],
		databaseURL:        variablesMap["DATABASE_URL"],
		redisURL:           variablesMap["REDIS_URL"],
		accountUsernameTTL: intMap["ACCOUNT_USERNAME_TTL"],
		frontendDomain:     variablesMap["FRONTEND_DOMAIN"],
		backendDomain:      variablesMap["BACKEND_DOMAIN"],
		cookieSecret:       variablesMap["COOKIE_SECRET"],
		cookieName:         variablesMap["COOKIE_NAME"],
		emailPubChannel:    variablesMap["EMAIL_PUB_CHANNEL"],
		serviceID:          uuid.MustParse(variablesMap["SERVICE_ID"]),
		loggerConfig: NewLoggerConfig(
			strings.ToLower(variablesMap["DEBUG"]) == "true",
			env,
			variablesMap["SERVICE_NAME"],
		),
		tokensConfig: NewTokensConfig(
			NewSingleJwtConfig(
				variablesMap["JWT_ACCESS_PUBLIC_KEY"],
				variablesMap["JWT_ACCESS_PRIVATE_KEY"],
				variablesMap["OLD_JWT_ACCESS_PUBLIC_KEY"],
				intMap["JWT_ACCESS_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_ACCOUNT_CREDENTIALS_PUBLIC_KEY"],
				variablesMap["JWT_ACCOUNT_CREDENTIALS_PRIVATE_KEY"],
				variablesMap["OLD_JWT_ACCOUNT_CREDENTIALS_PUBLIC_KEY"],
				intMap["JWT_ACCOUNT_CREDENTIALS_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_REFRESH_PUBLIC_KEY"],
				variablesMap["JWT_REFRESH_PRIVATE_KEY"],
				variablesMap["OLD_JWT_REFRESH_PUBLIC_KEY"],
				intMap["JWT_REFRESH_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_CONFIRM_PUBLIC_KEY"],
				variablesMap["JWT_CONFIRM_PRIVATE_KEY"],
				variablesMap["OLD_JWT_CONFIRM_PUBLIC_KEY"],
				intMap["JWT_CONFIRM_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_RESET_PUBLIC_KEY"],
				variablesMap["JWT_RESET_PRIVATE_KEY"],
				variablesMap["OLD_JWT_RESET_PUBLIC_KEY"],
				intMap["JWT_RESET_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_OAUTH_PUBLIC_KEY"],
				variablesMap["JWT_OAUTH_PRIVATE_KEY"],
				variablesMap["OLD_JWT_OAUTH_PUBLIC_KEY"],
				intMap["JWT_OAUTH_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_2FA_PUBLIC_KEY"],
				variablesMap["JWT_2FA_PRIVATE_KEY"],
				variablesMap["OLD_JWT_2FA_PUBLIC_KEY"],
				intMap["JWT_2FA_TTL_SEC"],
			),
			NewSingleJwtConfig(
				variablesMap["JWT_APPS_PUBLIC_KEY"],
				variablesMap["JWT_APPS_PRIVATE_KEY"],
				variablesMap["OLD_JWT_APPS_PUBLIC_KEY"],
				intMap["JWT_APPS_TTL_SEC"],
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
		encryptionConfig: NewEncryptionConfig(
			variablesMap["ACCOUNT_SECRET"],
			variablesMap["OIDC_SECRET"],
			variablesMap["USER_SECRET"],
			variablesMap["OLD_SECRETS"],
		),
	}
}
