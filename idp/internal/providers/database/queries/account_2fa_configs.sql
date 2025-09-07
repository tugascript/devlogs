-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccount2FAConfig :one
INSERT INTO "account_2fa_configs" (
    "account_id",
    "account_public_id",
    "two_factor_type",
    "is_default"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: FindDefaultAccount2FAConfigByAccountPublicID :one
SELECT * FROM "account_2fa_configs"
WHERE "account_public_id" = $1 AND "is_default" = true 
LIMIT 1;

-- name: FindAccount2FAConfigByAccountPublicIDAndType :one
SELECT * FROM "account_2fa_configs"
WHERE "account_public_id" = $1 AND "two_factor_type" = $2
LIMIT 1;

-- name: FindAccount2FAConfigsByAccountPublicID :many
SELECT * FROM "account_2fa_configs"
WHERE "account_public_id" = $1
ORDER BY "id" DESC;

-- name: UpdateAccount2FAConfig :one
UPDATE "account_2fa_configs" SET
    "is_default" = $2,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: DeleteAccount2FAConfig :exec
DELETE FROM "account_2fa_configs"
WHERE "id" = $1;

-- name: CountAccount2FAConfigsByAccountID :one
SELECT COUNT(*) FROM "account_2fa_configs"
WHERE "account_id" = $1
LIMIT 1;