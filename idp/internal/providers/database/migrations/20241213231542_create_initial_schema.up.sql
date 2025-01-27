-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2025-01-27T09:14:56.280Z

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
  "first_name" varchar(50) NOT NULL,
  "last_name" varchar(50) NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "is_confirmed" boolean NOT NULL DEFAULT false,
  "two_factor_type" varchar(5) NOT NULL DEFAULT 'none',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "accounts_totps" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "topt_url" varchar(250) NOT NULL,
  "secret_vault_id" uuid NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "account_keys" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "scopes" varchar(30)[] NOT NULL,
  "client_id" varchar(22) NOT NULL,
  "client_secret" text NOT NULL,
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
  "id" uuid PRIMARY KEY,
  "account_id" integer NOT NULL,
  "name" varchar(50) NOT NULL,
  "slug" varchar(60) NOT NULL,
  "redirect_uris" varchar(250)[] NOT NULL DEFAULT '[]',
  "sign_out_uri" varchar(250),
  "id_token_ttl" integer NOT NULL DEFAULT 3600,
  "secret" text NOT NULL,
  "jwt_crypto_suite" varchar(10) NOT NULL DEFAULT 'ecdsa',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "app_keys" (
  "id" serial PRIMARY KEY,
  "app_id" uuid NOT NULL,
  "account_id" integer NOT NULL,
  "jwt_crypto_suite" varchar(10) NOT NULL,
  "access_public_key" jsonb NOT NULL,
  "access_key_id" uuid NOT NULL,
  "id_public_key" jsonb NOT NULL,
  "id_key_id" uuid NOT NULL,
  "refresh_public_key" text NOT NULL,
  "refresh_key_id" uuid NOT NULL,
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "app_auth_providers" (
  "id" serial PRIMARY KEY,
  "app_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "email_password" boolean NOT NULL DEFAULT true,
  "google" boolean NOT NULL DEFAULT false,
  "facebook" boolean NOT NULL DEFAULT false,
  "github" boolean NOT NULL DEFAULT false,
  "apple" boolean NOT NULL DEFAULT false,
  "microsoft" boolean NOT NULL DEFAULT false,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "app_user_schemas" (
  "id" serial PRIMARY KEY,
  "app_id" integer NOT NULL,
  "account_id" integer NOT NULL,
  "name" boolean NOT NULL DEFAULT false,
  "gender" boolean NOT NULL DEFAULT false,
  "location" boolean NOT NULL DEFAULT false,
  "birth_date" boolean NOT NULL DEFAULT false,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "user_data" jsonb NOT NULL DEFAULT '{}',
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "user_totps" (
  "id" serial PRIMARY KEY,
  "user_id" integer NOT NULL,
  "topt_url" varchar(250) NOT NULL,
  "secret_vault_id" uuid NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "user_auth_provider" (
  "id" serial PRIMARY KEY,
  "email" varchar(250) NOT NULL,
  "provider" varchar(10) NOT NULL,
  "account_id" integer NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "blacklisted_tokens" (
  "id" uuid PRIMARY KEY,
  "jwt" text NOT NULL,
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE UNIQUE INDEX "accounts_totps_account_id_uidx" ON "accounts_totps" ("account_id");

CREATE UNIQUE INDEX "account_keys_client_id_uidx" ON "account_keys" ("client_id");

CREATE INDEX "account_keys_account_id_idx" ON "account_keys" ("account_id");

CREATE INDEX "auth_providers_email_idx" ON "auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "auth_providers" ("email", "provider");

CREATE INDEX "apps_account_id_idx" ON "apps" ("account_id");

CREATE UNIQUE INDEX "apps_slug_uidx" ON "apps" ("slug");

CREATE UNIQUE INDEX "app_keys_app_id_uidx" ON "app_keys" ("app_id");

CREATE INDEX "app_keys_account_id_idx" ON "app_keys" ("account_id");

CREATE UNIQUE INDEX "app_auth_providers_app_id_uidx" ON "app_auth_providers" ("app_id");

CREATE INDEX "app_auth_providers_account_id_idx" ON "app_auth_providers" ("account_id");

CREATE UNIQUE INDEX "app_user_schemas_app_id_uidx" ON "app_user_schemas" ("app_id");

CREATE INDEX "app_user_schemas_account_id_idx" ON "app_user_schemas" ("account_id");

CREATE UNIQUE INDEX "users_account_id_email_uidx" ON "users" ("account_id", "email");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE UNIQUE INDEX "user_totps_user_id_uidx" ON "user_totps" ("user_id");

CREATE INDEX "user_auth_provider_email_idx" ON "user_auth_provider" ("email");

CREATE UNIQUE INDEX "user_auth_provider_email_provider_uidx" ON "user_auth_provider" ("email", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_provider" ("account_id");

ALTER TABLE "accounts_totps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "account_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "apps" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_auth_providers" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_auth_providers" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "app_user_schemas" ADD FOREIGN KEY ("app_id") REFERENCES "apps" ("id") ON DELETE CASCADE;

ALTER TABLE "app_user_schemas" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "users" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_totps" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("email") REFERENCES "users" ("email") ON DELETE CASCADE;
