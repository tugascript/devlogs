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
    "expires_at"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: RevokeCredentialsSecret :one
UPDATE "credentials_secrets" SET
    "is_revoked" = true,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateCredentialsSecretExpiresAtAndCreatedAt :exec
UPDATE "credentials_secrets" SET
    "expires_at" = $2,
    "created_at" = $3,
    "updated_at" = now()
WHERE "secret_id" = $1;
