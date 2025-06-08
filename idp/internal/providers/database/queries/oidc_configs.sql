-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CountOIDCConfigsByAccountID :one
SELECT COUNT("id") FROM "oidc_configs"
WHERE "account_id" = $1;

-- name: CreateOIDCConfig :one
INSERT INTO "oidc_configs" (
    "account_id",
    "claims",
    "scopes",
    "dek"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: CreateDefaultOIDCConfig :one
INSERT INTO "oidc_configs" (
    "account_id",
    "dek"
) VALUES (
    $1,
    $2
) RETURNING *;

-- name: FindOIDCConfigByAccountID :one
SELECT * FROM "oidc_configs"
WHERE "account_id" = $1
LIMIT 1;

-- name: UpdateOIDCConfig :one
UPDATE "oidc_configs" SET
    "claims" = $1,
    "scopes" = $2,
    "updated_at" = now()
WHERE "id" = $3
RETURNING *;

-- name: UpdateOIDCConfigDek :exec
UPDATE "oidc_configs" SET
    "dek" = $1,
    "updated_at" = now()
WHERE "id" = $2;