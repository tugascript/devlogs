-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateApp :one
INSERT INTO "apps" (
  "account_id",
  "type",
  "name",
  "username_column",
  "client_id",
  "client_secret"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
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
    "confirmation_uri" = $3,
    "callback_uris" = $4,
    "logout_uris" = $5,
    "user_roles" = $6,
    "default_scopes" = $7,
    "auth_providers" = $8,
    "id_token_ttl" = $9,
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
