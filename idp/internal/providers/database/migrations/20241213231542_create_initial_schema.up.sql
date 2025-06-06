-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2025-06-02T00:30:26.782Z

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
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
  "two_factor_type" varchar(5) NOT NULL DEFAULT 'none',
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
  "scopes" jsonb NOT NULL,
  "alias" varchar(50) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "auth_providers" (
  "id" serial PRIMARY KEY,
  "email" varchar(250) NOT NULL,
  "provider" varchar(10) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "external_auth_providers" (
  "id" serial PRIMARY KEY,
  "name" varchar(50) NOT NULL,
  "provider" varchar(50) NOT NULL,
  "icon" text NOT NULL,
  "account_id" integer NOT NULL,
  "client_id" text NOT NULL,
  "client_secret" text NOT NULL,
  "scopes" varchar(250)[] NOT NULL,
  "auth_url" text NOT NULL,
  "token_url" text NOT NULL,
  "user_info_url" text NOT NULL,
  "email_key" varchar(50) NOT NULL,
  "user_schema" jsonb NOT NULL,
  "user_mapping" jsonb NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "oidc_configs" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "dek" text NOT NULL,
  "claims" jsonb NOT NULL DEFAULT '{ "given_name": true, "family_name": true }',
  "scopes" jsonb NOT NULL DEFAULT '{ "email": true, "profile": true, "openid": true }',
  "jwt_crypto_suite" varchar(7) NOT NULL DEFAULT 'ES256',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "account_keys" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "oidc_config_id" integer NOT NULL,
  "name" varchar(10) NOT NULL,
  "jwt_crypto_suite" varchar(5) NOT NULL,
  "public_kid" varchar(20) NOT NULL,
  "public_key" jsonb NOT NULL,
  "private_key" text NOT NULL,
  "is_distributed" boolean NOT NULL DEFAULT false,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "username" varchar(100) NOT NULL,
  "password" text,
  "dek" text NOT NULL,
  "version" integer NOT NULL DEFAULT 1,
  "email_verified" boolean NOT NULL DEFAULT false,
  "is_active" boolean NOT NULL DEFAULT true,
  "two_factor_type" varchar(5) NOT NULL DEFAULT 'none',
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
  "provider" varchar(50) NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "user_credentials" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "apps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "type" varchar(10) NOT NULL,
  "name" varchar(50) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "confirmation_uri" varchar(250) NOT NULL,
  "callback_uris" varchar(250)[] NOT NULL DEFAULT '{}',
  "logout_uris" varchar(250)[] NOT NULL DEFAULT '{}',
  "default_scopes" jsonb NOT NULL DEFAULT '{ "email": true, "openid": true }',
  "user_roles" jsonb NOT NULL DEFAULT '{ "user": true, "staff": true, "admin": true }',
  "auth_providers" jsonb NOT NULL DEFAULT '{ "username_password": true }',
  "username_column" varchar(8) NOT NULL DEFAULT 'email',
  "id_token_ttl" integer NOT NULL DEFAULT 3600,
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "app_profiles" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "user_id" integer NOT NULL,
  "app_id" integer NOT NULL,
  "user_roles" jsonb NOT NULL DEFAULT '{ "user": true }',
  "created_at" timestamptz NOT NULL DEFAULT (now()),
  "updated_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE TABLE "blacklisted_tokens" (
  "id" uuid PRIMARY KEY,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE UNIQUE INDEX "accounts_username_uidx" ON "accounts" ("username");

CREATE UNIQUE INDEX "accounts_totps_account_id_uidx" ON "account_totps" ("account_id");

CREATE UNIQUE INDEX "account_credentials_client_id_uidx" ON "account_credentials" ("client_id");

CREATE INDEX "account_credentials_account_id_idx" ON "account_credentials" ("account_id");

CREATE UNIQUE INDEX "account_credentials_alias_account_id_uidx" ON "account_credentials" ("alias", "account_id");

CREATE INDEX "auth_providers_email_idx" ON "auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "auth_providers" ("email", "provider");

CREATE UNIQUE INDEX "external_auth_providers_account_id_provider_uidx" ON "external_auth_providers" ("account_id", "provider");

CREATE INDEX "external_auth_providers_name_idx" ON "external_auth_providers" ("name");

CREATE INDEX "external_auth_providers_account_id_idx" ON "external_auth_providers" ("account_id");

CREATE UNIQUE INDEX "oidc_configs_account_id_uidx" ON "oidc_configs" ("account_id");

CREATE INDEX "account_keys_account_id_idx" ON "account_keys" ("account_id");

CREATE INDEX "account_keys_oidc_config_id_idx" ON "account_keys" ("oidc_config_id");

CREATE UNIQUE INDEX "account_keys_public_kid_uidx" ON "account_keys" ("public_kid");

CREATE INDEX "account_keys_name_account_id_expires_at_id_idx" ON "account_keys" ("name", "account_id", "expires_at", "id");

CREATE INDEX "account_keys_account_id_is_distributed_expires_at_idx" ON "account_keys" ("account_id", "is_distributed", "expires_at");

CREATE UNIQUE INDEX "users_account_id_email_uidx" ON "users" ("account_id", "email");

CREATE UNIQUE INDEX "users_account_id_username_uidx" ON "users" ("account_id", "username");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE INDEX "user_totps_account_id_idx" ON "user_totps" ("account_id");

CREATE UNIQUE INDEX "user_totps_user_id_uidx" ON "user_totps" ("user_id");

CREATE INDEX "user_auth_provider_user_id_idx" ON "user_auth_providers" ("user_id");

CREATE UNIQUE INDEX "user_auth_provider_user_id_provider_uidx" ON "user_auth_providers" ("user_id", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_providers" ("account_id");

CREATE UNIQUE INDEX "user_credentials_client_id_uidx" ON "user_credentials" ("client_id");

CREATE UNIQUE INDEX "user_credentials_user_id_uidx" ON "user_credentials" ("user_id");

CREATE INDEX "user_credentials_account_id_idx" ON "user_credentials" ("account_id");

CREATE INDEX "apps_account_id_idx" ON "apps" ("account_id");

CREATE UNIQUE INDEX "apps_client_id_uidx" ON "apps" ("client_id");

CREATE INDEX "apps_name_idx" ON "apps" ("name");

CREATE INDEX "apps_username_column_idx" ON "apps" ("username_column");

CREATE UNIQUE INDEX "apps_account_id_name_uidx" ON "apps" ("account_id", "name");

CREATE INDEX "user_profiles_account_id_idx" ON "app_profiles" ("account_id");

CREATE INDEX "user_profiles_user_id_idx" ON "app_profiles" ("user_id");

CREATE INDEX "user_profiles_app_id_idx" ON "app_profiles" ("app_id");

CREATE UNIQUE INDEX "user_profiles_user_id_app_id_uidx" ON "app_profiles" ("user_id", "app_id");

ALTER TABLE "account_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "external_auth_providers" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

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

ALTER TABLE "apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "app_profiles" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;
