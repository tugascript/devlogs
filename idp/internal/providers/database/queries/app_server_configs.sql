-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppServerConfig :one
INSERT INTO "app_server_configs" (
    "account_id",
    "app_id",
    "confirmation_url",
    "reset_password_url",
    "issuers"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: FindAppServerConfig :one
SELECT * FROM "app_server_configs"
WHERE "app_id" = $1 LIMIT 1;

-- name: UpdateAppServerConfig :one
UPDATE "app_server_configs"
SET "confirmation_url" = $3,
    "reset_password_url" = $4,
    "issuers" = $5,
    "updated_at" = now()
WHERE "account_id" = $1 AND "app_id" = $2
RETURNING *;