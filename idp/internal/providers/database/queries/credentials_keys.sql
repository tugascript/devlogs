-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateCredentialsKey :one
INSERT INTO "credentials_keys" (
    "account_id",
    "public_kid",
    "public_key",
    "crypto_suite",
    "expires_at",
    "usage"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING *;

-- name: RevokeCredentialsKey :one
UPDATE "credentials_keys" SET
    "is_revoked" = true,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateCredentialsKeyExpiresAtAndCreatedAt :exec
UPDATE "credentials_keys" SET
    "expires_at" = $2,
    "created_at" = $3,
    "updated_at" = now()
WHERE "public_kid" = $1;

-- name: FindCredentialsKeyPublicKeyByPublicKIDCryptoSuiteAndUsage :one
SELECT "public_key" FROM "credentials_keys"
WHERE
    "public_kid" = $1 AND
    "usage" = $2 AND
    "crypto_suite" = $3 AND
    "is_revoked" = false AND
    "expires_at" > now()
LIMIT 1;

-- name: DeleteAllCredentialsKeys :exec
DELETE FROM "credentials_keys";
