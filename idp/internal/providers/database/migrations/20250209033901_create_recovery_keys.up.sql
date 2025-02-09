CREATE TABLE "account_recovery_keys" (
    "id" serial PRIMARY KEY,
    "account_id" integer NOT NULL,
    "keys" jsonb NOT NULL,
    "created_at" timestamp NOT NULL DEFAULT (now()),
    "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE TABLE "user_recovery_keys" (
    "id" serial PRIMARY KEY,
    "user_id" integer NOT NULL,
    "keys" jsonb NOT NULL,
    "created_at" timestamp NOT NULL DEFAULT (now()),
    "updated_at" timestamp NOT NULL DEFAULT (now())
);

CREATE UNIQUE INDEX "account_recovery_keys_account_id_uidx" ON "account_recovery_keys" ("account_id");

CREATE UNIQUE INDEX "user_recovery_keys_user_id_uidx" ON "user_recovery_keys" ("user_id");

ALTER TABLE "account_recovery_keys" ADD FOREIGN KEY ("account_id") REFERENCES "accounts" ("id") ON DELETE CASCADE;

ALTER TABLE "user_recovery_keys" ADD FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE CASCADE;
