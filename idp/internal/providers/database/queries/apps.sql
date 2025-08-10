-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateApp :one
INSERT INTO "apps" (
  "account_id",
  "account_public_id",
  "app_type",
  "name",
  "client_id",
  "client_uri",
  "username_column",
  "token_endpoint_auth_method",
  "creation_source",
  "grant_types",
  "logo_uri",
  "tos_uri",
  "policy_uri",
  "contacts",
  "software_id",
  "software_version",
  "scopes",
  "default_scopes",
  "custom_scopes",
  "default_custom_scopes",
  "domain",
  "transport",
  "redirect_uris",
  "response_types",
  "allow_user_registration",
  "auth_providers"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $10,
  $11,
  $12,
  $13,
  $14,
  $15,
  $16,
  $17,
  $18,
  $19,
  $20,
  $21,
  $22,
  $23,
  $24,
  $25,
  $26
) RETURNING *;


-- name: CountAppsByAccountIDAndName :one
SELECT COUNT(*) FROM "apps"
WHERE "account_id" = $1 AND "name" = $2
LIMIT 1;

-- name: FindAppByClientID :one
SELECT * FROM "apps"
WHERE "client_id" = $1 LIMIT 1;

-- name: FindAppByClientIDAndAccountPublicID :one
SELECT * FROM "apps"
WHERE "client_id" = $1 AND "account_public_id" = $2
LIMIT 1;

-- name: FindAppByClientIDAndVersion :one
SELECT * FROM "apps"
WHERE "client_id" = $1 AND "version" = $2 LIMIT 1;

-- name: FindAppByID :one
SELECT * FROM "apps"
WHERE "id" = $1 LIMIT 1;

-- name: UpdateApp :one
UPDATE "apps"
SET "name" = $2,
    "username_column" = $3,
    "client_uri" = $4,
    "logo_uri" = $5,
    "tos_uri" = $6,
    "policy_uri" = $7,
    "software_id" = $8,
    "software_version" = $9,
    "contacts" = $10,
    "domain" = $11,
    "transport" = $12,
    "redirect_uris" = $13,
    "allow_user_registration" = $14,
    "response_types" = $15,
    "auth_providers" = $16,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateAppScopes :one
UPDATE "apps"
SET "scopes" = $2,
    "default_scopes" = $3,
    "custom_scopes" = $4,
    "default_custom_scopes" = $5,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: DeleteApp :exec
DELETE FROM "apps"
WHERE "id" = $1;

-- name: FindPaginatedAppsByAccountPublicIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: FindPaginatedAppsByAccountPublicIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1
ORDER BY "name" ASC
OFFSET $2 LIMIT $3;

-- name: CountAppsByAccountPublicID :one
SELECT COUNT(*) FROM "apps"
WHERE "account_public_id" = $1
LIMIT 1;

-- name: FilterAppsByNameAndByAccountPublicIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND "name" ILIKE $2
ORDER BY "id" DESC
OFFSET $3 LIMIT $4;

-- name: FilterAppsByTypeAndByAccountPublicIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND "app_type" = $2
ORDER BY "id" DESC
OFFSET $3 LIMIT $4;

-- name: FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByID :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND
  "name" ILIKE $2 AND
  "app_type" = $3
ORDER BY "id" DESC
OFFSET $4 LIMIT $5;

-- name: FilterAppsByNameAndByAccountPublicIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND "name" ILIKE $2
ORDER BY "name" ASC
OFFSET $3 LIMIT $4;

-- name: FilterAppsByTypeAndByAccountPublicIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND "app_type" = $2
ORDER BY "name" ASC
OFFSET $3 LIMIT $4;

-- name: FilterAppsByNameAndTypeAndByAccountPublicIDOrderedByName :many
SELECT * FROM "apps"
WHERE "account_public_id" = $1 AND
  "name" ILIKE $2 AND
  "app_type" = $3
ORDER BY "name" ASC
OFFSET $4 LIMIT $5;

-- name: CountFilteredAppsByNameAndByAccountPublicID :one
SELECT COUNT(*) FROM "apps"
WHERE "account_public_id" = $1 AND "name" ILIKE $2
LIMIT 1;

-- name: CountFilteredAppsByTypeAndByAccountPublicID :one
SELECT COUNT(*) FROM "apps"
WHERE "account_public_id" = $1 AND "app_type" = $2
LIMIT 1;

-- name: CountFilteredAppsByNameAndTypeAndByAccountPublicID :one
SELECT COUNT(*) FROM "apps"
WHERE "account_public_id" = $1 AND
  "name" ILIKE $2 AND
  "app_type" = $3
LIMIT 1;

-- name: UpdateAppVersion :one
UPDATE "apps" SET
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: FindAppsByClientIDsAndAccountID :many
SELECT * FROM "apps"
WHERE "client_id" IN (sqlc.slice('client_ids')) AND "account_id" = $1
ORDER BY "name" ASC LIMIT $2;

-- name: DeleteAllApps :exec
DELETE FROM "apps";
