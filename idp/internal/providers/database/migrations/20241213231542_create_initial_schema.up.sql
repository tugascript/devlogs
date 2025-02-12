-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2025-02-11T19:49:03.520Z

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
  "first_name" varchar(50) NOT NULL,
  "last_name" varchar(50) NOT NULL,
  "username" varchar(109) NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "is_confirmed" boolean NOT NULL DEFAULT false,
  "two_factor_type" varchar(5) NOT NULL DEFAULT 'none',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "account_totps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "url" varchar(250) NOT NULL,
  "secret" text NOT NULL,
  "dek" text NOT NULL,
  "recovery_codes" jsonb NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "account_credentials" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "scopes" jsonb NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "dek" text NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "auth_providers" (
  "id" serial PRIMARY KEY,
  "email" varchar(250) NOT NULL,
  "provider" varchar(10) NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "apps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "name" varchar(50) NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
  "dek" text NOT NULL,
  "callback_uris" varchar(250)[] NOT NULL DEFAULT '{}',
  "logout_uris" varchar(250)[] NOT NULL DEFAULT '{}',
  "user_scopes" jsonb NOT NULL DEFAULT '{ "email": true, "name": true }',
  "app_providers" jsonb NOT NULL DEFAULT '{ "email_password": true }',
  "id_token_ttl" integer NOT NULL DEFAULT 3600,
  "jwt_crypto_suite" varchar(7) NOT NULL DEFAULT 'ES256',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "app_keys" (
  "id" serial PRIMARY KEY,
  "app_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "name" varchar(10) NOT NULL,
  "jwt_crypto_suite" varchar(7) NOT NULL,
  "public_key" jsonb NOT NULL,
  "private_key" text NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "two_factor_type" varchar(5) NOT NULL DEFAULT 'none',
  "user_data" jsonb NOT NULL DEFAULT '{}',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "user_totps" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "url" varchar(250) NOT NULL,
  "secret" text NOT NULL,
  "dek" text NOT NULL,
  "recovery_codes" jsonb NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "user_auth_provider" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "provider" varchar(10) NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "blacklisted_tokens" (
  "id" uuid PRIMARY KEY,
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE UNIQUE INDEX "accounts_username_uidx" ON "accounts" ("username");

CREATE UNIQUE INDEX "accounts_totps_account_id_uidx" ON "account_totps" ("account_id");

CREATE UNIQUE INDEX "account_credentials_client_id_uidx" ON "account_credentials" ("client_id");

CREATE INDEX "account_credentials_account_id_idx" ON "account_credentials" ("account_id");

CREATE INDEX "auth_providers_email_idx" ON "auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "auth_providers" ("email", "provider");

CREATE INDEX "apps_account_id_idx" ON "apps" ("account_id");

CREATE UNIQUE INDEX "client_id_uidx" ON "apps" ("client_id");

CREATE INDEX "app_keys_app_id_idx" ON "app_keys" ("app_id");

CREATE INDEX "app_keys_account_id_idx" ON "app_keys" ("account_id");

CREATE UNIQUE INDEX "app_keys_name_app_id_uidx" ON "app_keys" ("name", "app_id");

CREATE UNIQUE INDEX "users_account_id_email_uidx" ON "users" ("account_id", "email");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE UNIQUE INDEX "user_totps_user_id_uidx" ON "user_totps" ("user_id");

CREATE INDEX "user_auth_provider_email_idx" ON "user_auth_provider" ("email");

CREATE INDEX "user_auth_provider_user_id_idx" ON "user_auth_provider" ("user_id");

CREATE UNIQUE INDEX "user_auth_provider_account_id_provider_uidx" ON "user_auth_provider" ("email", "account_id", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_provider" ("account_id");

ALTER TABLE "account_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_credentials" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "users" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;
