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
	env                  string
	maxProcs             int64
	databaseURL          string
	valkeyURL            string
	frontendDomain       string
	backendDomain        string
	cookieSecret         string
	cookieName           string
	emailPubChannel      string
	encryptionSecret     string
	serviceID            uuid.UUID
	serviceName          string
	loggerConfig         LoggerConfig
	tokensConfig         TokensConfig
	oAuthProvidersConfig OAuthProvidersConfig
	rateLimiterConfig    RateLimiterConfig
	openBaoConfig        OpenBaoConfig
	cryptoConfig         CryptoConfig
	distributedCache     DistributedCache
	kekExpirationDays    int64
	dekExpirationDays    int64
	jwkExpirationDays    int64
	accountCCExpDays     int64
	userCCExpDays        int64
	appCCExpDays         int64
}

func (c *Config) Port() int64 {
	return c.port
}

func (c *Config) Env() string {
	return c.env
}

func (c *Config) MaxProcs() int64 {
	return c.maxProcs
}

func (c *Config) DatabaseURL() string {
	return c.databaseURL
}

func (c *Config) ValkeyURL() string {
	return c.valkeyURL
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

func (c *Config) ServiceName() string {
	return c.serviceName
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

func (c *Config) OpenBaoConfig() OpenBaoConfig {
	return c.openBaoConfig
}

func (c *Config) CryptoConfig() CryptoConfig {
	return c.cryptoConfig
}

func (c *Config) DistributedCache() DistributedCache {
	return c.distributedCache
}

func (c *Config) KEKExpirationDays() int64 {
	return c.kekExpirationDays
}

func (c *Config) DEKExpirationDays() int64 {
	return c.dekExpirationDays
}

func (c *Config) JWKExpirationDays() int64 {
	return c.jwkExpirationDays
}

func (c *Config) AccountCCExpDays() int64 {
	return c.accountCCExpDays
}

func (c *Config) UserCCExpDays() int64 {
	return c.userCCExpDays
}

func (c *Config) AppCCExpDays() int64 {
	return c.appCCExpDays
}

var variables = [45]string{
	"PORT",
	"ENV",
	"DEBUG",
	"SERVICE_NAME",
	"SERVICE_ID",
	"MAX_PROCS",
	"DATABASE_URL",
	"VALKEY_URL",
	"FRONTEND_DOMAIN",
	"BACKEND_DOMAIN",
	"COOKIE_SECRET",
	"COOKIE_NAME",
	"RATE_LIMITER_MAX",
	"RATE_LIMITER_EXP_SEC",
	"EMAIL_PUB_CHANNEL",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCOUNT_CREDENTIALS_TTL_SEC",
	"JWT_REFRESH_TTL_SEC",
	"JWT_CONFIRM_TTL_SEC",
	"JWT_RESET_TTL_SEC",
	"JWT_2FA_TTL_SEC",
	"JWT_APPS_TTL_SEC",
	"OPENBAO_URL",
	"OPENBAO_DEV_TOKEN",
	"OPENBAO_ROLE_ID",
	"OPENBAO_SECRET_ID",
	"KEK_PATH",
	"DEK_TTL_SEC",
	"JWK_TTL_SEC",
	"KEK_EXPIRATION_DAYS",
	"DEK_EXPIRATION_DAYS",
	"JWK_EXPIRATION_DAYS",
	"KEK_CACHE_TTL_SEC",
	"DECRYPT_DEK_CACHE_TTL_SEC",
	"ENCRYPT_DEK_CACHE_TTL_SEC",
	"PUBLIC_JWK_CACHE_TTL_SEC",
	"PRIVATE_JWK_CACHE_TTL_SEC",
	"PUBLIC_JWKS_CACHE_TTL_SEC",
	"ACCOUNT_USERNAME_CACHE_TTL_SEC",
	"WELLKNOWN_OIDC_CONFIG_CACHE_TTL_SEC",
	"ACCOUNT_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"USER_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"APP_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"OAUTH_STATE_TTL_SEC",
	"OAUTH_CODE_TTL_SEC",
}

var optionalVariables = [10]string{
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
}

var numerics = [29]string{
	"PORT",
	"MAX_PROCS",
	"JWT_ACCESS_TTL_SEC",
	"JWT_ACCOUNT_CREDENTIALS_TTL_SEC",
	"JWT_REFRESH_TTL_SEC",
	"JWT_CONFIRM_TTL_SEC",
	"JWT_RESET_TTL_SEC",
	"JWT_2FA_TTL_SEC",
	"JWT_APPS_TTL_SEC",
	"RATE_LIMITER_MAX",
	"RATE_LIMITER_EXP_SEC",
	"DEK_TTL_SEC",
	"JWK_TTL_SEC",
	"KEK_EXPIRATION_DAYS",
	"DEK_EXPIRATION_DAYS",
	"JWK_EXPIRATION_DAYS",
	"KEK_CACHE_TTL_SEC",
	"DECRYPT_DEK_CACHE_TTL_SEC",
	"ENCRYPT_DEK_CACHE_TTL_SEC",
	"PUBLIC_JWK_CACHE_TTL_SEC",
	"PRIVATE_JWK_CACHE_TTL_SEC",
	"PUBLIC_JWKS_CACHE_TTL_SEC",
	"ACCOUNT_USERNAME_CACHE_TTL_SEC",
	"WELLKNOWN_OIDC_CONFIG_CACHE_TTL_SEC",
	"ACCOUNT_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"USER_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"APP_CLIENT_CREDENTIALS_EXPIRATION_DAYS",
	"OAUTH_STATE_TTL_SEC",
	"OAUTH_CODE_TTL_SEC",
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

	return Config{
		port:            intMap["PORT"],
		env:             variablesMap["ENV"],
		maxProcs:        intMap["MAX_PROCS"],
		databaseURL:     variablesMap["DATABASE_URL"],
		valkeyURL:       variablesMap["VALKEY_URL"],
		frontendDomain:  variablesMap["FRONTEND_DOMAIN"],
		backendDomain:   variablesMap["BACKEND_DOMAIN"],
		cookieSecret:    variablesMap["COOKIE_SECRET"],
		cookieName:      variablesMap["COOKIE_NAME"],
		emailPubChannel: variablesMap["EMAIL_PUB_CHANNEL"],
		serviceID:       uuid.MustParse(variablesMap["SERVICE_ID"]),
		serviceName:     variablesMap["SERVICE_NAME"],
		loggerConfig: NewLoggerConfig(
			strings.ToLower(variablesMap["DEBUG"]) == "true",
			variablesMap["ENV"],
			variablesMap["SERVICE_NAME"],
		),
		tokensConfig: NewTokensConfig(
			intMap["JWT_ACCESS_TTL_SEC"],
			intMap["JWT_ACCOUNT_CREDENTIALS_TTL_SEC"],
			intMap["JWT_REFRESH_TTL_SEC"],
			intMap["JWT_CONFIRM_TTL_SEC"],
			intMap["JWT_RESET_TTL_SEC"],
			intMap["JWT_2FA_TTL_SEC"],
			intMap["JWT_APPS_TTL_SEC"],
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
		openBaoConfig: NewOpenBaoConfig(
			variablesMap["OPENBAO_URL"],
			variablesMap["OPENBAO_DEV_TOKEN"],
			variablesMap["OPENBAO_ROLE_ID"],
			variablesMap["OPENBAO_SECRET_ID"],
		),
		cryptoConfig: NewEncryptionConfig(
			variablesMap["KEK_PATH"],
			intMap["DEK_TTL_SEC"],
			intMap["JWK_TTL_SEC"],
		),
		kekExpirationDays: intMap["KEK_EXPIRATION_DAYS"],
		dekExpirationDays: intMap["DEK_EXPIRATION_DAYS"],
		jwkExpirationDays: intMap["JWK_EXPIRATION_DAYS"],
		distributedCache: NewDistributedCache(
			intMap["KEK_CACHE_TTL_SEC"],
			intMap["DECRYPT_DEK_CACHE_TTL_SEC"],
			intMap["ENCRYPT_DEK_CACHE_TTL_SEC"],
			intMap["PUBLIC_JWK_CACHE_TTL_SEC"],
			intMap["PRIVATE_JWK_CACHE_TTL_SEC"],
			intMap["PUBLIC_JWKS_CACHE_TTL_SEC"],
			intMap["ACCOUNT_USERNAME_CACHE_TTL_SEC"],
			intMap["WELLKNOWN_OIDC_CONFIG_CACHE_TTL_SEC"],
			intMap["OAUTH_STATE_TTL_SEC"],
			intMap["OAUTH_CODE_TTL_SEC"],
		),
		accountCCExpDays: intMap["ACCOUNT_CLIENT_CREDENTIALS_EXPIRATION_DAYS"],
		userCCExpDays:    intMap["USER_CLIENT_CREDENTIALS_EXPIRATION_DAYS"],
		appCCExpDays:     intMap["APP_CLIENT_CREDENTIALS_EXPIRATION_DAYS"],
	}
}
