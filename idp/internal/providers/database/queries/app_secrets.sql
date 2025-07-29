-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppSecret :exec
INSERT INTO "app_secrets" (
    "app_id",
    "credentials_secret_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: FindPaginatedAppSecretsByAppID :many
SELECT "csr".* FROM "credentials_secrets" "csr"
LEFT JOIN "app_secrets" "as" ON "as"."credentials_secret_id" = "csr"."id"
WHERE "as"."app_id" = $1
ORDER BY "csr"."expires_at" DESC
OFFSET $2 LIMIT $3;

-- name: CountAppSecretsByAppID :one
SELECT COUNT(*) FROM "credentials_secrets" "csr"
LEFT JOIN "app_secrets" "as" ON "as"."credentials_secret_id" = "csr"."id"
WHERE "as"."app_id" = $1
LIMIT 1;

-- name: FindAppSecretByAppIDAndSecretID :one
SELECT "csr".* FROM "credentials_secrets" "csr"
LEFT JOIN "app_secrets" "as" ON "as"."credentials_secret_id" = "csr"."id"
WHERE 
    "as"."app_id" = $1 AND 
    "csr"."secret_id" = $2
LIMIT 1;
