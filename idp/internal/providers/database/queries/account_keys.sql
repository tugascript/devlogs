-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: DeleteDistributedAccountKeysByAccountID :exec
DELETE FROM "account_keys"
WHERE "account_id" = $1 AND "is_distributed" = true;

-- name: CreateAccountKey :one
INSERT INTO "account_keys" (
    "oidc_config_id",
    "account_id",
    "name",
    "jwt_crypto_suite",
    "public_kid",
    "public_key",
    "private_key",
    "is_distributed",
    "expires_at"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9
) RETURNING *;

-- name: FindAccountKeyByAccountIDAndName :one
SELECT * FROM "account_keys"
WHERE
    "account_id" = $1 AND
    "name" = $2 AND
    "expires_at" > $3
ORDER BY "id" DESC LIMIT 1;

-- name: FindAccountKeyByAccountIDAndNames :many
SELECT * FROM "account_keys"
WHERE
    "account_id" = $1 AND
    "name" = ANY(sqlc.slice('names')) AND
    "expires_at" > $2
ORDER BY "id" DESC;


-- name: FindAccountKeyByPublicKID :one
SELECT * FROM "account_keys"
WHERE "public_kid" = $1
LIMIT 1;


-- name: FindDistributedAccountKeysByAccountID :many
SELECT * FROM "account_keys"
WHERE
    "account_id" = $1 AND
    "is_distributed" = true AND
    "expires_at" > NOW()
ORDER BY "id" DESC;
