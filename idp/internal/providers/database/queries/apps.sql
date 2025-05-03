-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateApp :one
INSERT INTO "apps" (
  "account_id",
  "name",
  "username_column",
  "profile_schema",
  "client_id",
  "client_secret",
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

-- name: CreateDefaultApp :one
INSERT INTO "apps" (
    "account_id",
    "name",
    "client_id",
    "client_secret",
    "dek"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;


-- name: CountAppsByNameAndAccountID :one
SELECT COUNT("id") FROM "apps"
WHERE "account_id" = $1 AND "name" = $2
LIMIT 1;

-- name: FindAppByClientID :one
SELECT * FROM "apps"
WHERE "client_id" = $1 LIMIT 1;

-- name: FindAppByID :one
SELECT * FROM "apps"
WHERE "id" = $1 LIMIT 1;

-- name: UpdateApp :one
UPDATE "apps"
SET "name" = $2,
    "callback_uris" = $3,
    "logout_uris" = $4,
    "user_scopes" = $5,
    "app_providers" = $6,
    "id_token_ttl" = $7,
    "jwt_crypto_suite" = $8,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: DeleteApp :exec
DELETE FROM "apps"
WHERE "id" = $1;

-- name: FindPaginatedAppsByAccountIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: FindPaginatedAppsByAccountIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_id" = $1
ORDER BY "name" ASC
OFFSET $2 LIMIT $3;

-- name: CountAppsByAccountID :one
SELECT COUNT("id") FROM "apps"
WHERE "account_id" = $1
LIMIT 1;

-- name: FilterAppsByNameAndByAccountIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_id" = $1 AND "name" ILIKE $2
ORDER BY "id" DESC
OFFSET $3 LIMIT $4;

-- name: FilterAppsByNameAndByAccountIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_id" = $1 AND "name" ILIKE $2
ORDER BY "name" ASC
OFFSET $3 LIMIT $4;

-- name: CountFilteredAppsByNameAndByAccountID :one
SELECT COUNT("id") FROM "apps"
WHERE "account_id" = $1 AND "name" ILIKE $2
LIMIT 1;

-- name: UpdateAppClientSecret :one
UPDATE "apps" SET
    "client_secret" = $1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: UpdateAppDek :exec
UPDATE "apps" SET
    "dek" = $1,
    "updated_at" = now()
WHERE "id" = $2;
