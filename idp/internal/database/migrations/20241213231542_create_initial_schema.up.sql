-- SQL dump generated using DBML (dbml.dbdiagram.io)
-- Database: PostgreSQL
-- Generated at: 2024-12-14T08:00:08.820Z

CREATE TABLE "accounts" (
  "id" serial PRIMARY KEY,
  "first_name" varchar(50) NOT NULL,
  "last_name" varchar(50) NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
  "is_confirmed" boolean NOT NULL DEFAULT false,
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

CREATE TABLE "auth_keys" (
  "id" uuid PRIMARY KEY,
  "account_id" integer NOT NULL,
  "secret" text NOT NULL,
  "is_revoked" boolean NOT NULL DEFAULT false,
  "expires_at" timestamp,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "users" (
  "id" serial PRIMARY KEY,
  "account_id" integer NOT NULL,
  "name" varchar(100) NOT NULL,
  "username" varchar(50) NOT NULL,
  "email" varchar(250) NOT NULL,
  "password" text,
  "version" integer NOT NULL DEFAULT 1,
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
  "expires_at" timestamp NOT NULL,
  "created_at" timestamp NOT NULL DEFAULT (now()),
  "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "accounts_email_uidx" ON "accounts" ("email");

CREATE INDEX "auth_providers_email_idx" ON "auth_providers" ("email");

CREATE UNIQUE INDEX "auth_providers_email_provider_uidx" ON "auth_providers" ("email", "provider");

CREATE INDEX "auth_keys_account_id_idx" ON "auth_keys" ("account_id");

CREATE UNIQUE INDEX "users_username_uidx" ON "users" ("username");

CREATE UNIQUE INDEX "users_email_uidx" ON "users" ("email");

CREATE INDEX "users_account_id_idx" ON "users" ("account_id");

CREATE INDEX "user_auth_provider_email_idx" ON "user_auth_provider" ("email");

CREATE UNIQUE INDEX "user_auth_provider_email_provider_uidx" ON "user_auth_provider" ("email", "provider");

CREATE INDEX "user_auth_provider_account_id_idx" ON "user_auth_provider" ("account_id");

ALTER TABLE "auth_providers" ADD FOREIGN KEY ("email") REFERENCES "accounts" ("email") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "auth_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "users" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_auth_provider" ADD FOREIGN KEY ("email") REFERENCES "users" ("email") ON DELETE CASCADE;
