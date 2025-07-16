-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountWithPassword :one
INSERT INTO "accounts" (
    "public_id",
    "given_name",
    "family_name",
    "username",
    "email", 
    "password"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING *;

-- name: CreateAccountWithoutPassword :one
INSERT INTO "accounts" (
    "public_id",
    "given_name",
    "family_name",
    "username",
    "email",
    "version",
    "email_verified"
) VALUES (
    $1, 
    $2, 
    $3,
    $4,
    $5,
    2,
    true
) RETURNING *;

-- name: UpdateAccountEmail :one
UPDATE "accounts" SET
    "email" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: UpdateAccountPassword :one
UPDATE "accounts" SET
    "password" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: UpdateAccountUsername :one
UPDATE "accounts" SET
    "username" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: FindAccountByEmail :one
SELECT * FROM "accounts"
WHERE "email" = $1 LIMIT 1;

-- name: CountAccountsByEmail :one
SELECT COUNT("id") FROM "accounts"
WHERE "email" = $1 LIMIT 1;

-- name: FindAccountById :one
SELECT * FROM "accounts"
WHERE "id" = $1 LIMIT 1;

-- name: FindAccountByPublicID :one
SELECT * FROM "accounts"
WHERE "public_id" = $1 LIMIT 1;

-- name: CountAccountsByUsername :one
SELECT COUNT("id") FROM "accounts"
WHERE "username" = $1 LIMIT 1;

-- name: ConfirmAccount :one
UPDATE "accounts" SET
    "email_verified" = true,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateAccountTwoFactorType :exec
UPDATE "accounts" SET
    "two_factor_type" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2;

-- name: DeleteAllAccounts :exec
DELETE FROM "accounts";

-- name: DeleteAccount :exec
DELETE FROM "accounts"
WHERE "id" = $1;

-- name: UpdateAccount :one
UPDATE "accounts" SET
    "given_name" = $1,
    "family_name" = $2,
    "updated_at" = now()
WHERE "id" = $3
RETURNING *;

-- name: FindAccountIDByUsername :one
SELECT "id" FROM "accounts"
WHERE "username" = $1 LIMIT 1;

-- name: FindAccountIDByPublicIDAndVersion :one
SELECT "id" FROM "accounts"
WHERE "public_id" = $1 AND "version" = $2 LIMIT 1;

-- name: FindAccountByPublicIDAndVersion :one
SELECT * FROM "accounts"
WHERE "public_id" = $1 AND "version" = $2 LIMIT 1;
