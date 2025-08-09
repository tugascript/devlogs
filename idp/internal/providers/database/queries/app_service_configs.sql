-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppServiceConfig :one
INSERT INTO "app_service_configs" (
    "account_id",
    "app_id",
    "user_auth_method",
    "user_grant_types",
    "allowed_domains"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: FindAppServiceConfig :one
SELECT * FROM "app_service_configs"
WHERE "app_id" = $1 LIMIT 1;

-- name: UpdateAppServiceConfig :one
UPDATE "app_service_configs"
SET "allowed_domains" = $3,
    "updated_at" = now()
WHERE "account_id" = $1 AND "app_id" = $2
RETURNING *;