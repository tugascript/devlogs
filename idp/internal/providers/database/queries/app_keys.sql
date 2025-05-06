-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: DeleteDistributedAppKeysByAppID :exec
DELETE FROM "app_keys"
WHERE "app_id" = $1 AND "is_distributed" = true;

-- name: CreateAppKey :one
INSERT INTO "app_keys" (
    "app_id",
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

-- name: FindAppKeyByAppIDAndName :one
SELECT * FROM "app_keys"
WHERE
    "app_id" = $1 AND
    "name" = $2 AND
    "expires_at" > $3
ORDER BY "id" DESC LIMIT 1;

-- name: FindAppKeyByPublicKID :one
SELECT * FROM "app_keys"
WHERE "public_kid" = $1
LIMIT 1;

