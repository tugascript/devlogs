-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindAccountCredentialsByClientID :one
SELECT * FROM "account_credentials"
WHERE "client_id" = $1
LIMIT 1;

-- name: CreateAccountCredentials :one
INSERT INTO "account_credentials" (
    "client_id",
    "client_secret",
    "account_id",
    "alias",
    "scopes"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: UpdateAccountCredentialsClientSecret :one
UPDATE "account_credentials" SET
    "client_secret" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING *;

-- name: UpdateAccountCredentials :one
UPDATE "account_credentials" SET
    "scopes" = $1,
    "alias" = $2,
    "updated_at" = now()
WHERE "id" = $3
RETURNING *;

-- name: CountAccountCredentialsByAliasAndAccountID :one
SELECT COUNT("id") FROM "account_credentials"
WHERE "account_id" = $1 AND "alias" = $2;

-- name: DeleteAccountCredentials :exec
DELETE FROM "account_credentials"
WHERE "client_id" = $1;

-- name: FindPaginatedAccountCredentialsByAccountID :many
SELECT * FROM "account_credentials"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialsByAccountID :one
SELECT COUNT("id") FROM "account_credentials"
WHERE "account_id" = $1
LIMIT 1;