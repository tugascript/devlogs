-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateUserWithPassword :one
INSERT INTO "users" (
    "account_id",
    "public_id",
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
    $6,
    $7
) RETURNING *;

-- name: FindPaginatedUsersByAccountIDOrderedByID :many
SELECT * FROM "users"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: FindPaginatedUsersByAccountIDOrderedByEmail :many
SELECT * FROM "users"
WHERE "account_id" = $1
ORDER BY "email" ASC
OFFSET $2 LIMIT $3;

-- name: FindPaginatedUsersByAccountIDOrderedByUsername :many
SELECT * FROM "users"
WHERE "account_id" = $1
ORDER BY "username" ASC
OFFSET $2 LIMIT $3;

-- name: CountUsersByAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "account_id" = $1
LIMIT 1;

-- name: FilterUsersByEmailOrUsernameAndByAccountIDOrderedByID :many
SELECT * FROM "users"
WHERE "account_id" = $1 AND ("email" ILIKE $2 OR "username" ILIKE $3)
ORDER BY "id" DESC
OFFSET $4 LIMIT $5;

-- name: FilterUsersByEmailOrUsernameAndByAccountIDOrderedByEmail :many
SELECT * FROM "users"
WHERE "account_id" = $1 AND ("email" ILIKE $2 OR "username" ILIKE $3)
ORDER BY "email" ASC
OFFSET $4 LIMIT $5;

-- name: FilterUsersByEmailOrUsernameAndByAccountIDOrderedByUsername :many
SELECT * FROM "users"
WHERE "account_id" = $1 AND ("email" ILIKE $2 OR "username" ILIKE $3)
ORDER BY "username" ASC
OFFSET $4 LIMIT $5;

-- name: CountFilteredUsersByEmailOrUsernameAndByAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "account_id" = $1 AND ("email" ILIKE $2 OR "username" ILIKE $3)
LIMIT 1;

-- name: UpdateUser :one
UPDATE "users" SET
    "email" = $1,
    "username" = $2,
    "user_data" = $3,
    "is_active" = $4,
    "email_verified" = $5,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $6
RETURNING *;

-- name: UpdateUserPassword :one
UPDATE "users" SET
    "password" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM "users"
WHERE "id" = $1;

-- name: CreateUserWithoutPassword :one
INSERT INTO "users" (
    "account_id",
    "public_id",
    "email",
    "username",
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

-- name: CountUsersByUsernameAndAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "username" = $1 AND "account_id" = $2
LIMIT 1;

-- name: CountUsersByEmailAndAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "email" = $1 AND "account_id" = $2
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

-- name: FindUserByPublicIDAndVersion :one
SELECT * FROM "users"
WHERE "public_id" = $1 AND "version" = $2 LIMIT 1;

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
