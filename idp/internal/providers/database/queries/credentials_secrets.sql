-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateCredentialsSecret :one
INSERT INTO "credentials_secrets" (
    "account_id",
    "secret_id",
    "client_secret",
    "storage_mode",
    "dek_kid",
    "expires_at",
    "usage"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7
) RETURNING "id";

-- name: RevokeCredentialsSecret :one
UPDATE "credentials_secrets" SET
    "is_revoked" = true,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateCredentialsSecretClientSecret :exec
UPDATE "credentials_secrets" SET
    "client_secret" = $2,
    "dek_kid" = $3,
    "updated_at" = now()
WHERE "id" = $1;

-- name: UpdateCredentialsSecretExpiresAtAndCreatedAt :exec
UPDATE "credentials_secrets" SET
    "expires_at" = $2,
    "created_at" = $3,
    "updated_at" = now()
WHERE "secret_id" = $1;

-- name: FindCredentialsSecretBySecretIDAndUsage :one
SELECT * FROM "credentials_secrets"
WHERE
    "secret_id" = $1 AND
    "usage" = $2 AND
    "is_revoked" = false AND
    "expires_at" > now()
LIMIT 1;

-- name: DeleteAllCredentialsSecrets :exec
DELETE FROM "credentials_secrets";
