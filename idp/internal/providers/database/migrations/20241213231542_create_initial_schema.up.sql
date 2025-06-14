-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2025-06-14T12:14:30.638Z

CREATE TYPE "two_factor_type" AS ENUM (
  'none',
  'totp',
  'email'
);

CREATE TYPE "token_crypto_suite" AS ENUM (
  'ES256',
  'EdDSA'
);

CREATE TYPE "auth_method" AS ENUM (
  'none',
  'client_secret_basic',
  'client_secret_post',
  'private_key_jwt'
);

CREATE TYPE "account_credentials_scope" AS ENUM (
  'account:admin',
  'account:users:read',
  'account:users:write',
  'account:apps:read',
  'account:apps:write',
  'account:credentials:read',
  'account:credentials:write'
);

CREATE TYPE "auth_provider" AS ENUM (
  'username_password',
  'apple',
  'github',
  'google',
  'microsoft',
  'custom'
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
  'updated_at',
  'user_roles'
);

CREATE TYPE "scopes" AS ENUM (
  'openid',
  'email',
  'profile',
  'address',
  'phone',
  'user_roles',
  'account:users:authenticate'
);

CREATE TYPE "app_type" AS ENUM (
  'web',
  'native',
  'spa',
  'backend',
  'device',
  'service'
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

CREATE TYPE "response_type" AS ENUM (
  'code',
  'token',
  'id_token',
  'token id_token',
  'code id_token'
);

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
  "public_id" uuid NOT NULL,
  "given_name" varchar(50) NOT NULL,
  "family_name" varchar(50) NOT NULL,
  "username" varchar(63) NOT NULL,
  "email" varchar(250) NOT NULL,
  "organization" varchar(50),
  "dek" text NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "email_verified" boolean NOT NULL DEFAULT false,
  "is_active" boolean NOT NULL DEFAULT true,
  "two_factor_type" two_factor_type NOT NULL DEFAULT 'none',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "credentials_secrets" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "secret_id" varchar(26) NOT NULL,
  "client_secret" text NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "credentials_keys" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "public_kid" varchar(22) NOT NULL,
  "public_key" jsonb NOT NULL,
  "jwt_crypto_suite" token_crypto_suite NOT NULL DEFAULT 'ES256',
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_totps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "url" varchar(250) NOT NULL,
  "secret" text NOT NULL,
  "recovery_codes" jsonb NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_credentials" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "scopes" account_credentials_scope[] NOT NULL,
  "auth_methods" auth_method[] NOT NULL,
  "alias" varchar(50) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_credentials_secrets" (
  "account_credentials_id" integer NOT NULL,
  "credentials_secret_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_credentials_id", "credentials_secret_id")
);

CREATE TABLE "account_credentials_keys" (
  "account_credentials_id" integer NOT NULL,
  "credentials_key_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "account_public_id" uuid NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  PRIMARY KEY ("account_credentials_id", "credentials_key_id")
);

CREATE TABLE "account_auth_providers" (
  "id" serial PRIMARY KEY,
  "email" varchar(250) NOT NULL,
  "provider" auth_provider NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "oidc_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "dek" text NOT NULL,
  "claims_supported" claims[] NOT NULL DEFAULT '{ "sub", "email", "email_verified", "given_name", "family_name" }',
  "scopes_supported" scopes[] NOT NULL DEFAULT '{ "email", "profile" }',
  "user_roles_supported" varchar(50)[] NOT NULL DEFAULT '{ "user", "staff", "admin" }',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_keys" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "oidc_config_id" integer NOT NULL,
  "name" varchar(10) NOT NULL,
  "jwt_crypto_suite" token_crypto_suite NOT NULL,
  "public_kid" varchar(22) NOT NULL,
  "public_key" jsonb NOT NULL,
  "private_key" text NOT NULL,
  "is_distributed" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "public_id" uuid NOT NULL,
  "account_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "username" varchar(250) NOT NULL,
  "password" text,
  "dek" text NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "email_verified" boolean NOT NULL DEFAULT false,
  "user_roles" varchar(50)[] NOT NULL DEFAULT '{ "user" }',
  "is_active" boolean NOT NULL DEFAULT true,
  "two_factor_type" two_factor_type NOT NULL DEFAULT 'none',
  "user_data" jsonb NOT NULL DEFAULT '{}',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_totps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "url" varchar(250) NOT NULL,
  "secret" text NOT NULL,
  "recovery_codes" jsonb NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
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
  "client_id" varchar(22) NOT NULL,
  "auth_methods" auth_method[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_credentials_secrets" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "user_credential_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "secret_id" varchar(26) NOT NULL,
  "client_secret" text NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_credentials_keys" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "user_credential_id" integer NOT NULL,
  "public_kid" varchar(22) NOT NULL,
  "public_key" jsonb NOT NULL,
  "jwt_crypto_suite" token_crypto_suite NOT NULL DEFAULT 'ES256',
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "apps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "type" app_type NOT NULL,
  "name" varchar(50) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "client_uri" varchar(250),
  "logo_uri" varchar(250),
  "tos_uri" varchar(250),
  "policy_uri" varchar(250),
  "software_id" varchar(250),
  "software_version" varchar(250),
  "auth_methods" auth_method[] NOT NULL,
  "grant_types" grant_type[] NOT NULL,
  "response_types" response_type[] NOT NULL,
  "default_scopes" scopes[] NOT NULL DEFAULT '{ "openid", "email" }',
  "auth_providers" auth_provider[] NOT NULL DEFAULT '{ "username_password" }',
  "username_column" app_username_column NOT NULL DEFAULT 'email',
  "id_token_ttl" integer NOT NULL DEFAULT 3600,
  "token_ttl" integer NOT NULL DEFAULT 900,
  "refresh_token_ttl" integer NOT NULL DEFAULT 259200,
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

CREATE TABLE "app_uris" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "callback_uris" varchar(250)[] NOT NULL,
  "logout_uris" varchar(250)[] NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_server_urls" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "confirmation_url" varchar(250) NOT NULL,
  "reset_url" varchar(250) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_designs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "primary_light_color" varchar(6) NOT NULL,
  "primary_dark_color" varchar(6) NOT NULL,
  "secondary_light_color" varchar(6) NOT NULL,
  "secondary_dark_color" varchar(6) NOT NULL,
  "background_light_color" varchar(6) NOT NULL,
  "background_dark_color" varchar(6) NOT NULL,
  "text_light_color" varchar(6) NOT NULL,
  "text_dark_color" varchar(6) NOT NULL,
  "favicon_url" varchar(250),
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_profiles" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "revoked_tokens" (
  "id" serial PRIMARY KEY,
  "token_id" uuid NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE UNIQUE INDEX "accounts_public_id_uidx" ON "accounts" ("public_id");

CREATE INDEX "accounts_public_id_version_idx" ON "accounts" ("public_id", "version");

CREATE UNIQUE INDEX "accounts_username_uidx" ON "accounts" ("username");

CREATE INDEX "credential_secrets_account_id_idx" ON "credentials_secrets" ("account_id");

CREATE UNIQUE INDEX "credential_secrets_secret_id_uidx" ON "credentials_secrets" ("secret_id");

CREATE INDEX "credential_secrets_expires_at_idx" ON "credentials_secrets" ("expires_at");

CREATE INDEX "credential_secrets_is_revoked_expires_at_idx" ON "credentials_secrets" ("is_revoked", "expires_at");

CREATE INDEX "credential_secrets_account_id_secret_id_idx" ON "credentials_secrets" ("account_id", "secret_id");

CREATE INDEX "credential_keys_account_id_idx" ON "credentials_keys" ("account_id");

CREATE UNIQUE INDEX "credential_keys_public_kid_uidx" ON "credentials_keys" ("public_kid");

CREATE INDEX "credential_keys_expires_at_idx" ON "credentials_keys" ("expires_at");

CREATE INDEX "credential_keys_is_revoked_expires_at_idx" ON "credentials_keys" ("is_revoked", "expires_at");

CREATE INDEX "credential_keys_account_id_public_kid_idx" ON "credentials_keys" ("account_id", "public_kid");

CREATE UNIQUE INDEX "accounts_totps_account_id_uidx" ON "account_totps" ("account_id");

CREATE UNIQUE INDEX "account_credentials_client_id_uidx" ON "account_credentials" ("client_id");

CREATE INDEX "account_credentials_account_id_idx" ON "account_credentials" ("account_id");

CREATE INDEX "account_credentials_account_public_id_idx" ON "account_credentials" ("account_public_id");

CREATE INDEX "account_credentials_account_public_id_client_id_idx" ON "account_credentials" ("account_public_id", "client_id");

CREATE UNIQUE INDEX "account_credentials_alias_account_id_uidx" ON "account_credentials" ("alias", "account_id");

CREATE INDEX "account_credentials_secrets_account_credentials_id_idx" ON "account_credentials_secrets" ("account_credentials_id");

CREATE UNIQUE INDEX "account_credentials_secrets_credentials_secret_id_uidx" ON "account_credentials_secrets" ("credentials_secret_id");

CREATE INDEX "account_credentials_secrets_account_id_idx" ON "account_credentials_secrets" ("account_id");

CREATE INDEX "account_credentials_keys_account_credentials_id_idx" ON "account_credentials_keys" ("account_credentials_id");

CREATE UNIQUE INDEX "account_credentials_keys_credentials_key_id_uidx" ON "account_credentials_keys" ("credentials_key_id");

CREATE INDEX "account_credentials_keys_account_id_idx" ON "account_credentials_keys" ("account_id");

CREATE INDEX "account_credentials_keys_account_public_id_idx" ON "account_credentials_keys" ("account_public_id");

CREATE INDEX "auth_providers_email_idx" ON "account_auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "account_auth_providers" ("email", "provider");

CREATE UNIQUE INDEX "oidc_configs_account_id_uidx" ON "oidc_configs" ("account_id");

CREATE INDEX "account_keys_account_id_idx" ON "account_keys" ("account_id");

CREATE INDEX "account_keys_oidc_config_id_idx" ON "account_keys" ("oidc_config_id");

CREATE UNIQUE INDEX "account_keys_public_kid_uidx" ON "account_keys" ("public_kid");

CREATE INDEX "account_keys_account_id_public_kid_idx" ON "account_keys" ("account_id", "public_kid");

CREATE INDEX "account_keys_name_account_id_expires_at_id_idx" ON "account_keys" ("name", "account_id", "expires_at", "id");

CREATE INDEX "account_keys_account_id_is_distributed_expires_at_idx" ON "account_keys" ("account_id", "is_distributed", "expires_at");

CREATE UNIQUE INDEX "users_account_id_email_uidx" ON "users" ("account_id", "email");

CREATE UNIQUE INDEX "users_account_id_username_uidx" ON "users" ("account_id", "username");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE UNIQUE INDEX "users_public_id_uidx" ON "users" ("public_id");

CREATE INDEX "users_public_id_version_idx" ON "users" ("public_id", "version");

CREATE INDEX "user_totps_account_id_idx" ON "user_totps" ("account_id");

CREATE UNIQUE INDEX "user_totps_user_id_uidx" ON "user_totps" ("user_id");

CREATE INDEX "user_auth_provider_user_id_idx" ON "user_auth_providers" ("user_id");

CREATE UNIQUE INDEX "user_auth_provider_user_id_provider_uidx" ON "user_auth_providers" ("user_id", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_providers" ("account_id");

CREATE UNIQUE INDEX "user_credentials_client_id_uidx" ON "user_credentials" ("client_id");

CREATE UNIQUE INDEX "user_credentials_user_id_uidx" ON "user_credentials" ("user_id");

CREATE INDEX "user_credentials_account_id_idx" ON "user_credentials" ("account_id");

CREATE INDEX "user_credentials_secrets_user_id_idx" ON "user_credentials_secrets" ("user_id");

CREATE INDEX "user_credentials_secrets_user_credential_id_idx" ON "user_credentials_secrets" ("user_credential_id");

CREATE UNIQUE INDEX "user_credentials_secrets_secret_id_uidx" ON "user_credentials_secrets" ("secret_id");

CREATE INDEX "user_credentials_secrets_user_credential_id_secret_id_idx" ON "user_credentials_secrets" ("user_credential_id", "secret_id");

CREATE INDEX "user_credentials_secrets_account_id_idx" ON "user_credentials_secrets" ("account_id");

CREATE INDEX "user_credentials_keys_account_id_idx" ON "user_credentials_keys" ("account_id");

CREATE INDEX "user_credentials_keys_user_id_idx" ON "user_credentials_keys" ("user_id");

CREATE INDEX "user_credentials_keys_user_credential_id_idx" ON "user_credentials_keys" ("user_credential_id");

CREATE UNIQUE INDEX "user_credentials_keys_public_kid_uidx" ON "user_credentials_keys" ("public_kid");

CREATE INDEX "user_credentials_keys_user_credential_id_public_kid_idx" ON "user_credentials_keys" ("user_credential_id", "public_kid");

CREATE INDEX "apps_account_id_idx" ON "apps" ("account_id");

CREATE INDEX "apps_type_idx" ON "apps" ("type");

CREATE UNIQUE INDEX "apps_client_id_uidx" ON "apps" ("client_id");

CREATE INDEX "apps_client_id_version_idx" ON "apps" ("client_id", "version");

CREATE INDEX "apps_name_idx" ON "apps" ("name");

CREATE UNIQUE INDEX "apps_account_id_name_uidx" ON "apps" ("account_id", "name");

CREATE INDEX "apps_account_id_type_idx" ON "apps" ("account_id", "type");

CREATE INDEX "app_secrets_app_id_idx" ON "app_secrets" ("app_id");

CREATE UNIQUE INDEX "app_secrets_credentials_secret_id_uidx" ON "app_secrets" ("credentials_secret_id");

CREATE INDEX "app_secrets_account_id_idx" ON "app_secrets" ("account_id");

CREATE INDEX "app_keys_app_id_idx" ON "app_keys" ("app_id");

CREATE UNIQUE INDEX "app_keys_credentials_key_id_uidx" ON "app_keys" ("credentials_key_id");

CREATE INDEX "app_keys_account_id_idx" ON "app_keys" ("account_id");

CREATE INDEX "app_uris_account_id_idx" ON "app_uris" ("account_id");

CREATE UNIQUE INDEX "app_uris_app_id_uidx" ON "app_uris" ("app_id");

CREATE INDEX "app_server_urls_account_id_idx" ON "app_server_urls" ("account_id");

CREATE UNIQUE INDEX "app_server_urls_app_id_uidx" ON "app_server_urls" ("app_id");

CREATE INDEX "app_designs_account_id_idx" ON "app_designs" ("account_id");

CREATE UNIQUE INDEX "app_designs_app_id_uidx" ON "app_designs" ("app_id");

CREATE INDEX "user_profiles_account_id_idx" ON "app_profiles" ("account_id");

CREATE INDEX "user_profiles_user_id_idx" ON "app_profiles" ("user_id");

CREATE INDEX "user_profiles_app_id_idx" ON "app_profiles" ("app_id");

CREATE UNIQUE INDEX "user_profiles_user_id_app_id_uidx" ON "app_profiles" ("user_id", "app_id");

CREATE UNIQUE INDEX "revoked_tokens_token_id_uidx" ON "revoked_tokens" ("token_id");

ALTER TABLE "credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_secrets" ADD FOREIGN KEY ("account_credentials_id") REFERENCES "account_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_secrets" ADD FOREIGN KEY ("credentials_secret_id") REFERENCES "credentials_secrets" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("account_credentials_id") REFERENCES "account_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials_keys" ADD FOREIGN KEY ("credentials_key_id") REFERENCES "credentials_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "account_auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "oidc_configs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_keys" ADD FOREIGN KEY ("oidc_config_id") REFERENCES "oidc_configs" ("id") ON DELETE CASCADE;

ALTER TABLE "users" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_providers" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_providers" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("user_credential_id") REFERENCES "user_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("user_credential_id") REFERENCES "user_credentials" ("id") ON DELETE CASCADE;

ALTER TABLE "user_credentials_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_secrets" ADD FOREIGN KEY ("credentials_secret_id") REFERENCES "credentials_secrets" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("credentials_key_id") REFERENCES "credentials_keys" ("id") ON DELETE CASCADE;

ALTER TABLE "app_uris" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_uris" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_server_urls" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_server_urls" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_designs" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_designs" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;
