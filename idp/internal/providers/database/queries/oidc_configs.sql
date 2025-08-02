-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CountOIDCConfigsByAccountID :one
SELECT COUNT(*) FROM "oidc_configs"
WHERE "account_id" = $1;

-- name: CreateOIDCConfig :one
INSERT INTO "oidc_configs" (
    "account_id",
    "claims_supported",
    "scopes_supported",
    "custom_claims",
    "custom_scopes"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: CreateDefaultOIDCConfig :one
INSERT INTO "oidc_configs" (
    "account_id"
) VALUES (
    $1
) RETURNING *;

-- name: FindOIDCConfigByAccountID :one
SELECT * FROM "oidc_configs"
WHERE "account_id" = $1
LIMIT 1;

-- name: UpdateOIDCConfig :one
UPDATE "oidc_configs" SET
    "claims_supported" = $2,
    "scopes_supported" = $3,
    "custom_claims" = $4,
    "custom_scopes" = $5,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;
