-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2025-08-17T08:47:57.041Z

CREATE TYPE "kek_usage" AS ENUM (
  'global',
  'account'
);

CREATE TYPE "dek_usage" AS ENUM (
  'global',
  'account',
  'user'
);

CREATE TYPE "token_crypto_suite" AS ENUM (
  'ES256',
  'EdDSA'
);

CREATE TYPE "token_key_usage" AS ENUM (
  'global',
  'account'
);

CREATE TYPE "token_key_type" AS ENUM (
  'access',
  'refresh',
  'id_token',
  'client_credentials',
  'email_verification',
  'password_reset',
  '2fa_authentication',
  'dynamic_registration'
);

CREATE TYPE "two_factor_type" AS ENUM (
  'none',
  'totp',
  'email'
);

CREATE TYPE "totp_usage" AS ENUM (
  'account',
  'user'
);

CREATE TYPE "credentials_usage" AS ENUM (
  'account',
  'app',
  'user'
);

CREATE TYPE "secret_storage_mode" AS ENUM (
  'hashed',
  'encrypted'
);

CREATE TYPE "auth_method" AS ENUM (
  'none',
  'client_secret_basic',
  'client_secret_post',
  'client_secret_jwt',
  'private_key_jwt'
);

CREATE TYPE "response_type" AS ENUM (
  'code',
  'id_token',
  'code id_token'
);

CREATE TYPE "account_credentials_scope" AS ENUM (
  'email',
  'profile',
  'account:admin',
  'account:users:read',
  'account:users:write',
  'account:apps:read',
  'account:apps:write',
  'account:apps:configs:read',
  'account:apps:configs:write',
  'account:credentials:read',
  'account:credentials:write',
  'account:credentials:configs:read',
  'account:credentials:configs:write',
  'account:auth_providers:read'
);

CREATE TYPE "account_credentials_type" AS ENUM (
  'native',
  'service',
  'mcp'
);

CREATE TYPE "transport" AS ENUM (
  'http',
  'https',
  'stdio',
  'streamable_http'
);

CREATE TYPE "creation_method" AS ENUM (
  'manual',
  'dynamic_registration'
);

CREATE TYPE "auth_provider" AS ENUM (
  'local',
  'apple',
  'facebook',
  'github',
  'google',
  'microsoft'
);

CREATE TYPE "claims" AS ENUM (
  'sub',
  'name',
  'given_name',
  'family_name',
  'middle_name',
  'nickname',
  'preferred_username',
  'profile',
  'picture',
  'website',
  'email',
  'email_verified',
  'gender',
  'birthdate',
  'zoneinfo',
  'locale',
  'phone_number',
  'phone_number_verified',
  'address',
  'updated_at'
);

CREATE TYPE "scopes" AS ENUM (
  'openid',
  'email',
  'profile',
  'address',
  'phone'
);

CREATE TYPE "app_type" AS ENUM (
  'web',
  'native',
  'spa',
  'backend',
  'device',
  'service',
  'mcp'
);

CREATE TYPE "app_username_column" AS ENUM (
  'email',
  'username',
  'both'
);

CREATE TYPE "grant_type" AS ENUM (
  'authorization_code',
  'refresh_token',
  'client_credentials',
  'urn:ietf:params:oauth:grant-type:device_code',
  'urn:ietf:params:oauth:grant-type:jwt-bearer'
);

CREATE TYPE "initial_access_token_generation_method" AS ENUM (
  'manual',
  'authorization_code'
);

CREATE TYPE "software_statement_verification_method" AS ENUM (
  'manual',
  'jwks_uri'
);

CREATE TYPE "domain_verification_method" AS ENUM (
  'authorization_code',
  'software_statement',
  'dns_txt_record'
);

CREATE TYPE "app_profile_type" AS ENUM (
  'human',
  'machine',
  'ai_agent'
);

CREATE TYPE "token_owner" AS ENUM (
  'user',
  'account'
);

CREATE TABLE "key_encryption_keys" (
  "id" serial PRIMARY KEY,
  "kid" uuid NOT NULL,
  "usage" kek_usage NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "rotated_at" timestamptz NOT NULL DEFAULT (now()),
  "next_rotation_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "data_encryption_keys" (
  "id" serial PRIMARY KEY,
  "kid" varchar(22) NOT NULL,
  "dek" text NOT NULL,
  "kek_kid" uuid NOT NULL,
  "usage" dek_usage NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "token_signing_keys" (
  "id" serial PRIMARY KEY,
  "kid" varchar(22) NOT NULL,
  "key_type" token_key_type NOT NULL,
  "public_key" jsonb NOT NULL,
  "private_key" text NOT NULL,
  "dek_kid" varchar(22) NOT NULL,
  "crypto_suite" token_crypto_suite NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "usage" token_key_usage NOT NULL DEFAULT 'account',
  "is_distributed" boolean NOT NULL DEFAULT false,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
  "public_id" uuid NOT NULL,
  "given_name" varchar(100) NOT NULL,
  "family_name" varchar(100) NOT NULL,
  "username" varchar(63) NOT NULL,
  "email" varchar(250) NOT NULL,
  "organization" varchar(50),
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "email_verified" boolean NOT NULL DEFAULT false,
  "is_active" boolean NOT NULL DEFAULT true,
  "two_factor_type" two_factor_type NOT NULL DEFAULT 'none',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "totps" (
  "id" serial PRIMARY KEY,
  "dek_kid" varchar(22) NOT NULL,
  "url" varchar(512) NOT NULL,
  "secret" text NOT NULL,
  "recovery_codes" jsonb NOT NULL,
  "usage" totp_usage NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "credentials_secrets" (
  "id" serial PRIMARY KEY,
  "secret_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "storage_mode" secret_storage_mode NOT NULL,
  "dek_kid" varchar(22),
  "is_revoked" boolean NOT NULL DEFAULT false,
  "usage" credentials_usage NOT NULL,
  "account_id" integer NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "credentials_keys" (
  "id" serial PRIMARY KEY,
  "public_kid" varchar(22) NOT NULL,
  "public_key" jsonb NOT NULL,
  "crypto_suite" token_crypto_suite NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "usage" credentials_usage NOT NULL,
  "account_id" integer NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_key_encryption_keys" (
  "account_id" integer NOT NULL,
  "key_encryption_key_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "key_encryption_key_id")
);

CREATE TABLE "account_data_encryption_keys" (
  "account_id" integer NOT NULL,
  "data_encryption_key_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "data_encryption_key_id")
);

CREATE TABLE "account_hmac_secrets" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "secret_id" varchar(22) NOT NULL,
  "secret" text NOT NULL,
  "dek_kid" varchar(22) NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_totps" (
  "account_id" integer NOT NULL,
  "totp_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "totp_id")
);

CREATE TABLE "account_credentials" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "name" varchar(255) NOT NULL,
  "domain" varchar(250) NOT NULL,
  "credentials_type" account_credentials_type NOT NULL,
  "scopes" account_credentials_scope[] NOT NULL,
  "token_endpoint_auth_method" auth_method NOT NULL,
  "grant_types" grant_type[] NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "transport" transport NOT NULL,
  "creation_method" creation_method NOT NULL,
  "client_uri" varchar(512) NOT NULL,
  "redirect_uris" varchar(2048)[] NOT NULL,
  "logo_uri" varchar(512),
  "policy_uri" varchar(512),
  "tos_uri" varchar(512),
  "software_id" varchar(512) NOT NULL,
  "software_version" varchar(512),
  "contacts" varchar(250)[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_credentials_secrets" (
  "account_id" integer NOT NULL,
  "credentials_secret_id" integer NOT NULL,
  "account_credentials_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "secret_id" varchar(22) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "credentials_secret_id")
);

CREATE TABLE "account_credentials_keys" (
  "account_id" integer NOT NULL,
  "credentials_key_id" integer NOT NULL,
  "account_credentials_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "jwk_kid" varchar(22) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "credentials_key_id")
);

CREATE TABLE "account_auth_providers" (
  "id" serial PRIMARY KEY,
  "email" varchar(250) NOT NULL,
  "provider" auth_provider NOT NULL,
  "account_public_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "oidc_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "claims_supported" claims[] NOT NULL DEFAULT '{ "sub", "email", "email_verified", "given_name", "family_name" }',
  "scopes_supported" scopes[] NOT NULL DEFAULT '{ "openid", "email", "profile" }',
  "custom_claims" varchar(512)[] NOT NULL DEFAULT '{}',
  "custom_scopes" varchar(512)[] NOT NULL DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_token_signing_keys" (
  "account_id" integer NOT NULL,
  "token_signing_key_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_id", "token_signing_key_id")
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "public_id" uuid NOT NULL,
  "account_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "username" varchar(63) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "email_verified" boolean NOT NULL DEFAULT false,
  "is_active" boolean NOT NULL DEFAULT true,
  "two_factor_type" two_factor_type NOT NULL DEFAULT 'none',
  "user_data" jsonb NOT NULL DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_data_encryption_keys" (
  "user_id" integer NOT NULL,
  "data_encryption_key_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("user_id", "data_encryption_key_id")
);

CREATE TABLE "user_totps" (
  "user_id" integer NOT NULL,
  "totp_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("user_id", "totp_id")
);

CREATE TABLE "user_auth_providers" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "provider" auth_provider NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_credentials" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "auth_methods" auth_method[] NOT NULL,
  "issuers" varchar(512)[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_credentials_secrets" (
  "user_id" integer NOT NULL,
  "credentials_secret_id" integer NOT NULL,
  "user_credential_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "user_public_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("user_id", "credentials_secret_id")
);

CREATE TABLE "user_credentials_keys" (
  "user_id" integer NOT NULL,
  "credentials_key_id" integer NOT NULL,
  "user_credential_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "user_public_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("user_id", "credentials_key_id")
);

CREATE TABLE "apps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "app_type" app_type NOT NULL,
  "name" varchar(255) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "creation_method" creation_method NOT NULL,
  "client_uri" varchar(512) NOT NULL,
  "logo_uri" varchar(512),
  "tos_uri" varchar(512),
  "policy_uri" varchar(512),
  "software_id" varchar(250) NOT NULL,
  "software_version" varchar(250),
  "contacts" varchar(250)[] NOT NULL,
  "token_endpoint_auth_method" auth_method NOT NULL,
  "scopes" scopes[] NOT NULL,
  "custom_scopes" varchar(512)[] NOT NULL,
  "grant_types" grant_type[] NOT NULL,
  "domain" varchar(250) NOT NULL,
  "transport" transport NOT NULL,
  "allow_user_registration" bool NOT NULL,
  "auth_providers" auth_provider[] NOT NULL,
  "username_column" app_username_column NOT NULL,
  "default_scopes" scopes[] NOT NULL,
  "default_custom_scopes" varchar(512)[] NOT NULL,
  "redirect_uris" varchar(2048)[] NOT NULL,
  "response_types" response_type[] NOT NULL,
  "id_token_ttl" integer NOT NULL DEFAULT 300,
  "token_ttl" integer NOT NULL DEFAULT 300,
  "refresh_token_ttl" integer NOT NULL DEFAULT 604800,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_secrets" (
  "app_id" integer NOT NULL,
  "credentials_secret_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("app_id", "credentials_secret_id")
);

CREATE TABLE "app_keys" (
  "app_id" integer NOT NULL,
  "credentials_key_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("app_id", "credentials_key_id")
);

CREATE TABLE "app_related_apps" (
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "related_app_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("app_id", "related_app_id")
);

CREATE TABLE "app_service_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "user_auth_method" auth_method NOT NULL,
  "user_grant_types" grant_type[] NOT NULL,
  "allowed_domains" varchar(250)[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_designs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "light_colors" jsonb NOT NULL,
  "dark_colors" jsonb,
  "logo_url" varchar(512),
  "favicon_url" varchar(512),
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_dynamic_registration_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "account_credentials_types" account_credentials_type[] NOT NULL,
  "whitelisted_domains" varchar(250)[] NOT NULL,
  "require_software_statement_credential_types" account_credentials_type[] NOT NULL,
  "software_statement_verification_methods" software_statement_verification_method[] NOT NULL,
  "require_initial_access_token_credential_types" account_credentials_type[] NOT NULL,
  "initial_access_token_generation_methods" initial_access_token_generation_method[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_dynamic_registration_domains" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "domain" varchar(250) NOT NULL,
  "verified_at" timestamptz,
  "verification_method" domain_verification_method NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "dynamic_registration_domain_codes" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "verification_host" varchar(50) NOT NULL,
  "verification_code" text NOT NULL,
  "hmac_secret_id" varchar(22) NOT NULL,
  "verification_prefix" varchar(70) NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_dynamic_registration_domain_codes" (
  "account_dynamic_registration_domain_id" integer NOT NULL,
  "dynamic_registration_domain_code_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_dynamic_registration_domain_id", "dynamic_registration_domain_code_id")
);

CREATE TABLE "app_dynamic_registration_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "allowed_app_types" app_type[] NOT NULL,
  "whitelisted_domains" varchar(250)[] NOT NULL,
  "default_allow_user_registration" boolean NOT NULL,
  "default_auth_providers" auth_provider[] NOT NULL,
  "default_username_column" app_username_column NOT NULL,
  "default_allowed_scopes" scopes[] NOT NULL,
  "default_scopes" scopes[] NOT NULL,
  "require_software_statement_app_types" app_type[] NOT NULL,
  "software_statement_verification_methods" software_statement_verification_method[] NOT NULL,
  "require_initial_access_token_app_types" app_type[] NOT NULL,
  "initial_access_token_generation_methods" initial_access_token_generation_method[] NOT NULL,
  "initial_access_token_ttl" integer NOT NULL DEFAULT 3600,
  "initial_access_token_max_uses" int NOT NULL DEFAULT 1,
  "allowed_grant_types" grant_type[] NOT NULL DEFAULT '{ "authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:jwt-bearer" }',
  "allowed_response_types" response_type[] NOT NULL DEFAULT '{ "code", "id_token", "code id_token" }',
  "allowed_token_endpoint_auth_methods" auth_method[] NOT NULL DEFAULT '{ "none", "client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt" }',
  "max_redirect_uris" int NOT NULL DEFAULT 10,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_profiles" (
  "app_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "profile_type" app_profile_type NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("app_id", "user_id")
);

CREATE TABLE "revoked_tokens" (
  "id" serial PRIMARY KEY,
  "token_id" uuid NOT NULL,
  "account_id" integer NOT NULL,
  "owner" token_owner NOT NULL,
  "owner_public_id" uuid NOT NULL,
  "issued_at" timestamptz NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "key_encryption_keys_kid_uidx" ON "key_encryption_keys" ("kid");

CREATE INDEX "key_encryption_keys_usage_idx" ON "key_encryption_keys" ("usage");

CREATE UNIQUE INDEX "key_encryption_keys_kid_usage_uidx" ON "key_encryption_keys" ("kid", "usage");

CREATE UNIQUE INDEX "data_encryption_keys_kid_uidx" ON "data_encryption_keys" ("kid");

CREATE INDEX "data_encryption_keys_expires_at_idx" ON "data_encryption_keys" ("expires_at");

CREATE INDEX "data_encryption_keys_is_revoked_expires_at_idx" ON "data_encryption_keys" ("is_revoked", "expires_at");

CREATE INDEX "data_encryption_keys_usage_is_revoked_expires_at_idx" ON "data_encryption_keys" ("usage", "is_revoked", "expires_at");

CREATE INDEX "data_encryption_keys_kek_kid_idx" ON "data_encryption_keys" ("kek_kid");

CREATE UNIQUE INDEX "token_signing_keys_kid_uidx" ON "token_signing_keys" ("kid");

CREATE INDEX "token_signing_keys_expires_at_idx" ON "token_signing_keys" ("expires_at");

CREATE INDEX "token_signing_keys_is_distributed_is_revoked_expires_at_idx" ON "token_signing_keys" ("is_distributed", "is_revoked", "expires_at");

CREATE INDEX "token_signing_keys_key_type_usage_is_revoked_expires_at_idx" ON "token_signing_keys" ("key_type", "usage", "is_revoked", "expires_at");

CREATE INDEX "token_signing_keys_usage_is_distributed_is_revoked_expires_at_idx" ON "token_signing_keys" ("usage", "is_distributed", "is_revoked", "expires_at");

CREATE INDEX "token_signing_keys_kid_is_revoked_idx" ON "token_signing_keys" ("kid", "is_revoked");

CREATE INDEX "token_signing_keys_dek_kid_idx" ON "token_signing_keys" ("dek_kid");

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE UNIQUE INDEX "accounts_public_id_uidx" ON "accounts" ("public_id");

CREATE INDEX "accounts_public_id_version_idx" ON "accounts" ("public_id", "version");

CREATE UNIQUE INDEX "accounts_username_uidx" ON "accounts" ("username");

CREATE INDEX "accounts_totps_dek_kid_idx" ON "totps" ("dek_kid");

CREATE INDEX "accounts_totps_account_id_idx" ON "totps" ("account_id");

CREATE UNIQUE INDEX "credential_secrets_secret_id_uidx" ON "credentials_secrets" ("secret_id");

CREATE INDEX "credential_secrets_expires_at_idx" ON "credentials_secrets" ("expires_at");

CREATE INDEX "credential_secrets_is_revoked_usage_expires_at_idx" ON "credentials_secrets" ("is_revoked", "usage", "expires_at");

CREATE INDEX "credential_secrets_secret_id_is_revoked_expires_at_idx" ON "credentials_secrets" ("secret_id", "is_revoked", "expires_at");

CREATE INDEX "credential_secrets_dek_kid_idx" ON "credentials_secrets" ("dek_kid");

CREATE INDEX "credential_secrets_account_id_idx" ON "credentials_secrets" ("account_id");

CREATE UNIQUE INDEX "credential_keys_public_kid_uidx" ON "credentials_keys" ("public_kid");

CREATE INDEX "credential_keys_expires_at_idx" ON "credentials_keys" ("expires_at");

CREATE INDEX "credential_keys_is_revoked_usage_expires_at_idx" ON "credentials_keys" ("is_revoked", "usage", "expires_at");

CREATE INDEX "credential_keys_public_kid_crypto_suite_usage_is_revoked_expires_at_idx" ON "credentials_keys" ("public_kid", "crypto_suite", "usage", "is_revoked", "expires_at");

CREATE INDEX "account_key_encryption_keys_account_id_idx" ON "account_key_encryption_keys" ("account_id");

CREATE UNIQUE INDEX "account_key_encryption_keys_key_encryption_key_id_uidx" ON "account_key_encryption_keys" ("key_encryption_key_id");

CREATE UNIQUE INDEX "account_key_encryption_keys_account_id_key_encryption_key_id_uidx" ON "account_key_encryption_keys" ("account_id", "key_encryption_key_id");

CREATE INDEX "account_data_encryption_keys_account_id_idx" ON "account_data_encryption_keys" ("account_id");

CREATE UNIQUE INDEX "account_data_encryption_keys_data_encryption_key_id_uidx" ON "account_data_encryption_keys" ("data_encryption_key_id");

CREATE UNIQUE INDEX "account_data_encryption_keys_account_id_data_encryption_key_id_uidx" ON "account_data_encryption_keys" ("account_id", "data_encryption_key_id");

CREATE INDEX "account_hmac_secrets_account_id_idx" ON "account_hmac_secrets" ("account_id");

CREATE UNIQUE INDEX "account_hmac_secrets_secret_id_uidx" ON "account_hmac_secrets" ("secret_id");

CREATE INDEX "account_hmac_secrets_dek_kid_idx" ON "account_hmac_secrets" ("dek_kid");

CREATE INDEX "account_hmac_secrets_account_id_secret_id_idx" ON "account_hmac_secrets" ("account_id", "secret_id");

CREATE INDEX "account_hmac_secrets_account_id_is_revoked_expires_at_idx" ON "account_hmac_secrets" ("account_id", "is_revoked", "expires_at");

CREATE UNIQUE INDEX "accounts_totps_account_id_uidx" ON "account_totps" ("account_id");

CREATE UNIQUE INDEX "accounts_totps_totp_id_uidx" ON "account_totps" ("totp_id");

CREATE UNIQUE INDEX "accounts_totps_account_id_totp_id_uidx" ON "account_totps" ("account_id", "totp_id");

CREATE UNIQUE INDEX "account_credentials_client_id_uidx" ON "account_credentials" ("client_id");

CREATE INDEX "account_credentials_account_id_idx" ON "account_credentials" ("account_id");

CREATE INDEX "account_credentials_account_public_id_idx" ON "account_credentials" ("account_public_id");

CREATE INDEX "account_credentials_account_public_id_client_id_idx" ON "account_credentials" ("account_public_id", "client_id");

CREATE UNIQUE INDEX "account_credentials_name_account_id_uidx" ON "account_credentials" ("name", "account_id");

CREATE INDEX "account_credential_secrets_account_id_idx" ON "account_credentials_secrets" ("account_id");

CREATE INDEX "account_credential_secrets_account_public_id_idx" ON "account_credentials_secrets" ("account_public_id");

CREATE UNIQUE INDEX "account_credential_secrets_credentials_secret_id_uidx" ON "account_credentials_secrets" ("credentials_secret_id");

CREATE INDEX "account_credential_secrets_account_credentials_id_idx" ON "account_credentials_secrets" ("account_credentials_id");

CREATE INDEX "account_credential_secrets_account_credentials_id_secret_id_idx" ON "account_credentials_secrets" ("account_credentials_id", "secret_id");

CREATE INDEX "account_credentials_keys_account_id_idx" ON "account_credentials_keys" ("account_id");

CREATE UNIQUE INDEX "account_credentials_keys_credentials_key_id_uidx" ON "account_credentials_keys" ("credentials_key_id");

CREATE INDEX "account_credentials_keys_account_credentials_id_idx" ON "account_credentials_keys" ("account_credentials_id");

CREATE INDEX "account_credentials_keys_account_public_id_idx" ON "account_credentials_keys" ("account_public_id");

CREATE INDEX "account_credentials_account_credentials_id_keys_jwk_kid_idx" ON "account_credentials_keys" ("account_credentials_id", "jwk_kid");

CREATE INDEX "auth_providers_email_idx" ON "account_auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "account_auth_providers" ("email", "provider");

CREATE INDEX "auth_providers_account_public_id_idx" ON "account_auth_providers" ("account_public_id");

CREATE INDEX "auth_providers_account_public_id_email_idx" ON "account_auth_providers" ("account_public_id", "email");

CREATE UNIQUE INDEX "oidc_configs_account_id_uidx" ON "oidc_configs" ("account_id");

CREATE INDEX "account_token_signing_keys_account_id_idx" ON "account_token_signing_keys" ("account_id");

CREATE UNIQUE INDEX "account_token_signing_keys_token_signing_key_id_uidx" ON "account_token_signing_keys" ("token_signing_key_id");

CREATE UNIQUE INDEX "account_token_signing_keys_account_id_token_signing_key_id_uidx" ON "account_token_signing_keys" ("account_id", "token_signing_key_id");

CREATE UNIQUE INDEX "users_account_id_email_uidx" ON "users" ("account_id", "email");

CREATE UNIQUE INDEX "users_account_id_username_uidx" ON "users" ("account_id", "username");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE UNIQUE INDEX "users_public_id_uidx" ON "users" ("public_id");

CREATE INDEX "users_public_id_version_idx" ON "users" ("public_id", "version");

CREATE INDEX "user_data_encryption_keys_user_id_idx" ON "user_data_encryption_keys" ("user_id");

CREATE UNIQUE INDEX "user_data_encryption_keys_data_encryption_key_id_uidx" ON "user_data_encryption_keys" ("data_encryption_key_id");

CREATE INDEX "user_data_encryption_keys_account_id_idx" ON "user_data_encryption_keys" ("account_id");

CREATE UNIQUE INDEX "user_data_encryption_keys_user_id_data_encryption_key_id_uidx" ON "user_data_encryption_keys" ("user_id", "data_encryption_key_id");

CREATE UNIQUE INDEX "user_totps_user_id_uidx" ON "user_totps" ("user_id");

CREATE UNIQUE INDEX "user_totps_totp_id_uidx" ON "user_totps" ("totp_id");

CREATE INDEX "user_totps_account_id_idx" ON "user_totps" ("account_id");

CREATE UNIQUE INDEX "user_totps_user_id_totp_id_uidx" ON "user_totps" ("user_id", "totp_id");

CREATE INDEX "user_auth_provider_user_id_idx" ON "user_auth_providers" ("user_id");

CREATE UNIQUE INDEX "user_auth_provider_user_id_provider_uidx" ON "user_auth_providers" ("user_id", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_providers" ("account_id");

CREATE UNIQUE INDEX "user_credentials_client_id_uidx" ON "user_credentials" ("client_id");

CREATE INDEX "user_credentials_user_id_idx" ON "user_credentials" ("user_id");

CREATE INDEX "user_credentials_account_id_idx" ON "user_credentials" ("account_id");

CREATE INDEX "user_credentials_app_id_idx" ON "user_credentials" ("app_id");

CREATE UNIQUE INDEX "user_credentials_user_id_app_id_uidx" ON "user_credentials" ("user_id", "app_id");

CREATE INDEX "user_credentials_secrets_user_id_idx" ON "user_credentials_secrets" ("user_id");

CREATE UNIQUE INDEX "user_credentials_secrets_credentials_secret_id_uidx" ON "user_credentials_secrets" ("credentials_secret_id");

CREATE INDEX "user_credentials_secrets_account_id_idx" ON "user_credentials_secrets" ("account_id");

CREATE INDEX "user_credentials_secrets_user_credential_id_idx" ON "user_credentials_secrets" ("user_credential_id");

CREATE INDEX "user_credentials_secrets_user_public_id_idx" ON "user_credentials_secrets" ("user_public_id");

CREATE UNIQUE INDEX "user_credentials_secrets_user_id_user_credential_id_uidx" ON "user_credentials_secrets" ("user_id", "user_credential_id");

CREATE INDEX "user_credentials_keys_user_id_idx" ON "user_credentials_keys" ("user_id");

CREATE UNIQUE INDEX "user_credentials_keys_credentials_key_id_uidx" ON "user_credentials_keys" ("credentials_key_id");

CREATE INDEX "user_credentials_keys_account_id_idx" ON "user_credentials_keys" ("account_id");

CREATE INDEX "user_credentials_keys_user_credential_id_idx" ON "user_credentials_keys" ("user_credential_id");

CREATE INDEX "user_credentials_keys_user_public_id_idx" ON "user_credentials_keys" ("user_public_id");

CREATE UNIQUE INDEX "user_credentials_keys_user_id_user_credential_id_uidx" ON "user_credentials_keys" ("user_id", "user_credential_id");

CREATE INDEX "apps_account_id_idx" ON "apps" ("account_id");

CREATE INDEX "apps_app_type_idx" ON "apps" ("app_type");

CREATE UNIQUE INDEX "apps_client_id_uidx" ON "apps" ("client_id");

CREATE INDEX "apps_client_id_account_public_id_idx" ON "apps" ("client_id", "account_public_id");

CREATE INDEX "apps_account_public_id_idx" ON "apps" ("account_public_id");

CREATE INDEX "apps_name_idx" ON "apps" ("name");

CREATE UNIQUE INDEX "apps_account_id_name_uidx" ON "apps" ("account_id", "name");

CREATE INDEX "apps_account_id_app_type_idx" ON "apps" ("account_id", "app_type");

CREATE INDEX "app_secrets_app_id_idx" ON "app_secrets" ("app_id");

CREATE UNIQUE INDEX "app_secrets_credentials_secret_id_uidx" ON "app_secrets" ("credentials_secret_id");

CREATE INDEX "app_secrets_account_id_idx" ON "app_secrets" ("account_id");

CREATE UNIQUE INDEX "app_secrets_app_id_credentials_secret_id_uidx" ON "app_secrets" ("app_id", "credentials_secret_id");

CREATE INDEX "app_keys_app_id_idx" ON "app_keys" ("app_id");

CREATE UNIQUE INDEX "app_keys_credentials_key_id_uidx" ON "app_keys" ("credentials_key_id");

CREATE INDEX "app_keys_account_id_idx" ON "app_keys" ("account_id");

CREATE UNIQUE INDEX "app_keys_app_id_credentials_key_id_uidx" ON "app_keys" ("app_id", "credentials_key_id");

CREATE INDEX "app_related_apps_account_id_idx" ON "app_related_apps" ("account_id");

CREATE INDEX "app_related_apps_app_id_idx" ON "app_related_apps" ("app_id");

CREATE INDEX "app_related_apps_related_app_id_idx" ON "app_related_apps" ("related_app_id");

CREATE UNIQUE INDEX "app_related_apps_app_id_related_app_id_uidx" ON "app_related_apps" ("app_id", "related_app_id");

CREATE INDEX "app_service_configs_account_id_idx" ON "app_service_configs" ("account_id");

CREATE UNIQUE INDEX "app_service_configs_app_id_uidx" ON "app_service_configs" ("app_id");

CREATE INDEX "app_designs_account_id_idx" ON "app_designs" ("account_id");

CREATE UNIQUE INDEX "app_designs_app_id_uidx" ON "app_designs" ("app_id");

CREATE UNIQUE INDEX "account_dynamic_registration_configs_account_id_uidx" ON "account_dynamic_registration_configs" ("account_id");

CREATE INDEX "account_dynamic_registration_configs_account_public_id_idx" ON "account_dynamic_registration_configs" ("account_public_id");

CREATE INDEX "accounts_totps_account_id_idx" ON "account_dynamic_registration_domains" ("account_id");

CREATE INDEX "account_dynamic_registration_domains_account_public_id_idx" ON "account_dynamic_registration_domains" ("account_public_id");

CREATE INDEX "account_dynamic_registration_domains_domain_idx" ON "account_dynamic_registration_domains" ("domain");

CREATE UNIQUE INDEX "account_dynamic_registration_domains_account_public_id_domain_uidx" ON "account_dynamic_registration_domains" ("account_public_id", "domain");

CREATE INDEX "account_dynamic_registration_domain_codes_account_id_idx" ON "dynamic_registration_domain_codes" ("account_id");

CREATE INDEX "account_dynamic_registration_domain_codes_account_id_idx" ON "account_dynamic_registration_domain_codes" ("account_id");

CREATE UNIQUE INDEX "account_dynamic_registration_domain_codes_account_dynamic_registration_domain_id_uidx" ON "account_dynamic_registration_domain_codes" ("account_dynamic_registration_domain_id");

CREATE UNIQUE INDEX "account_dynamic_registration_domain_codes_dynamic_registration_domain_code_id_uidx" ON "account_dynamic_registration_domain_codes" ("dynamic_registration_domain_code_id");

CREATE INDEX "app_dynamic_registration_configs_account_id_idx" ON "app_dynamic_registration_configs" ("account_id");

CREATE INDEX "user_profiles_app_id_idx" ON "app_profiles" ("app_id");

CREATE INDEX "user_profiles_user_id_idx" ON "app_profiles" ("user_id");

CREATE INDEX "user_profiles_account_id_idx" ON "app_profiles" ("account_id");

CREATE UNIQUE INDEX "user_profiles_user_id_app_id_uidx" ON "app_profiles" ("user_id", "app_id");

CREATE UNIQUE INDEX "revoked_tokens_token_id_uidx" ON "revoked_tokens" ("token_id");

CREATE INDEX "revoked_tokens_account_id_idx" ON "revoked_tokens" ("account_id");

CREATE INDEX "revoked_tokens_expires_at_idx" ON "revoked_tokens" ("expires_at");

ALTER TABLE "data_encryption_keys" ADD FOREIGN KEY ("kek_kid") REFERENCES "key_encryption_keys" ("kid") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "token_signing_keys" ADD FOREIGN KEY ("dek_kid") REFERENCES "data_encryption_keys" ("kid") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "totps" ADD FOREIGN KEY ("dek_kid") REFERENCES "data_encryption_keys" ("kid") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "credentials_secrets" ADD FOREIGN KEY ("dek_kid") REFERENCES "data_encryption_keys" ("kid") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_key_encryption_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_key_encryption_keys" ADD FOREIGN KEY ("key_encryption_key_id") REFERENCES "key_encryption_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "account_data_encryption_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_data_encryption_keys" ADD FOREIGN KEY ("data_encryption_key_id") REFERENCES "data_encryption_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "account_hmac_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_hmac_secrets" ADD FOREIGN KEY ("dek_kid") REFERENCES "data_encryption_keys" ("kid") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "account_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_totps" ADD FOREIGN KEY ("totp_id") REFERENCES "totps" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_secrets" ADD FOREIGN KEY ("credentials_secret_id") REFERENCES "credentials_secrets" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("account_credentials_id") REFERENCES "account_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("credentials_key_id") REFERENCES "credentials_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "account_auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "oidc_configs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_token_signing_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_token_signing_keys" ADD FOREIGN KEY ("token_signing_key_id") REFERENCES "token_signing_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "users" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_data_encryption_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_data_encryption_keys" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_data_encryption_keys" ADD FOREIGN KEY ("data_encryption_key_id") REFERENCES "data_encryption_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("totp_id") REFERENCES "totps" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_providers" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_providers" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("user_credential_id") REFERENCES "user_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("credentials_secret_id") REFERENCES "credentials_secrets" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("user_credential_id") REFERENCES "user_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("credentials_key_id") REFERENCES "credentials_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("credentials_secret_id") REFERENCES "credentials_secrets" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("credentials_key_id") REFERENCES "credentials_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "app_related_apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_related_apps" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_related_apps" ADD FOREIGN KEY ("related_app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_service_configs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_service_configs" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_designs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_designs" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "account_dynamic_registration_configs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_dynamic_registration_domains" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "dynamic_registration_domain_codes" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "dynamic_registration_domain_codes" ADD FOREIGN KEY ("hmac_secret_id") REFERENCES "account_hmac_secrets" ("secret_id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "account_dynamic_registration_domain_codes" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_dynamic_registration_domain_codes" ADD FOREIGN KEY ("account_dynamic_registration_domain_id") REFERENCES "account_dynamic_registration_domains" ("id") ON DELETE CASCADE;

ALTER TABLE "account_dynamic_registration_domain_codes" ADD FOREIGN KEY ("dynamic_registration_domain_code_id") REFERENCES "dynamic_registration_domain_codes" ("id") ON DELETE CASCADE;

ALTER TABLE "app_dynamic_registration_configs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "revoked_tokens" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;
