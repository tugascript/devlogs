-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindAccountCredentialsByClientID :one
SELECT * FROM "account_credentials"
WHERE "client_id" = $1
LIMIT 1;

-- name: FindAccountCredentialsByAccountPublicIDAndClientID :one
SELECT * FROM "account_credentials"
WHERE "account_public_id" = $1 AND "client_id" = $2
LIMIT 1;

-- name: CreateAccountCredentials :one
INSERT INTO "account_credentials" (
    "client_id",
    "account_id",
    "account_public_id",
    "credentials_type",
    "name",
    "scopes",
    "token_endpoint_auth_method",
    "domain",
    "client_uri",
    "redirect_uris",
    "logo_uri",
    "policy_uri",
    "tos_uri",
    "software_id",
    "software_version",
    "contacts",
    "creation_method",
    "transport"
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
    $18
) RETURNING *;

-- name: UpdateAccountCredentials :one
UPDATE "account_credentials" SET
    "scopes" = $2,
    "name" = $3,
    "domain" = $4,
    "client_uri" = $5,
    "redirect_uris" = $6,
    "logo_uri" = $7,
    "policy_uri" = $8,
    "tos_uri" = $9,
    "software_version" = $10,
    "contacts" = $11,
    "transport" = $12,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: CountAccountCredentialsByNameAndAccountID :one
SELECT COUNT(*) FROM "account_credentials"
WHERE "account_id" = $1 AND "name" = $2;

-- name: DeleteAccountCredentials :exec
DELETE FROM "account_credentials"
WHERE "client_id" = $1;

-- name: FindPaginatedAccountCredentialsByAccountPublicID :many
SELECT * FROM "account_credentials"
WHERE "account_public_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialsByAccountPublicID :one
SELECT COUNT(*) FROM "account_credentials"
WHERE "account_public_id" = $1
LIMIT 1;

-- name: DeleteAllAccountCredentials :exec
DELETE FROM "account_credentials";
