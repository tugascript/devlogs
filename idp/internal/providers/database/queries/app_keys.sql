-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppKey :exec
INSERT INTO "app_keys" (
    "app_id",
    "credentials_key_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: FindPaginatedAppKeysByAppID :many
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "app_keys" "ak" ON "ak"."credentials_key_id" = "ckr"."id"
WHERE "ak"."app_id" = $1
ORDER BY "ckr"."expires_at" DESC
OFFSET $2 LIMIT $3;

-- name: CountAppKeysByAppID :one
SELECT COUNT("ckr"."id") FROM "credentials_keys" "ckr"
LEFT JOIN "app_keys" "ak" ON "ak"."credentials_key_id" = "ckr"."id"
WHERE "ak"."app_id" = $1
LIMIT 1;

-- name: FindAppKeyByAppIDAndPublicKID :one
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "app_keys" "ak" ON "ak"."credentials_key_id" = "ckr"."id"
WHERE 
    "ak"."app_id" = $1 AND 
    "ckr"."public_kid" = $2
LIMIT 1;
