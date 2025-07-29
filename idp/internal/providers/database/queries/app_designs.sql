-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppDesign :one
INSERT INTO "app_designs" (
    "account_id",
    "app_id",
    "light_colors",
    "dark_colors",
    "logo_url",
    "favicon_url"
) VALUES (
    $1, 
    $2, 
    $3, 
    $4, 
    $5, 
    $6
) RETURNING *;

-- name: CountAppDesignsByAppID :one
SELECT COUNT(*) FROM "app_designs" WHERE "app_id" = $1
LIMIT 1;

-- name: FindAppDesignByAppID :one
SELECT * FROM "app_designs" WHERE "app_id" = $1
LIMIT 1;

-- name: UpdateAppDesign :one
UPDATE "app_designs" SET
    "light_colors" = $1,
    "dark_colors" = $2,
    "logo_url" = $3,
    "favicon_url" = $4
WHERE "id" = $5
RETURNING *;

-- name: DeleteAppDesign :exec
DELETE FROM "app_designs" WHERE "id" = $1;

-- name: DeleteAllAppDesigns :exec
DELETE FROM "app_designs";