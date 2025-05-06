-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateUserWithPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "username",
    "password",
    "user_data",
    "dek"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING *;

-- name: CreateUserWithoutPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "username",
    "user_data",
    "dek"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: CountUsersByUsernameAndAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "username" = $1 AND "account_id" = $2
LIMIT 1;

-- name: CountUsersByEmailAndAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "email" = $1 AND "account_id" = $2
LIMIT 1;

-- name: CountUsersByAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "account_id" = $1
LIMIT 1;

-- name: ConfirmUser :one
UPDATE "users" SET
    "is_confirmed" = true,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: FindUserByID :one
SELECT * FROM "users"
WHERE "id" = $1 LIMIT 1;

-- name: FindUserByUsernameAndAccountID :one
SELECT * FROM "users"
WHERE "username" = $1 AND "account_id" = $2
LIMIT 1;

-- name: FindUserByEmailAndAccountID :one
SELECT * FROM "users"
WHERE "email" = $1 AND "account_id" = $2
LIMIT 1;

-- name: UpdateUserDEK :exec
UPDATE "users" SET
    "dek" = $1,
    "updated_at" = now()
WHERE "id" = $2;
