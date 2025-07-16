-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateTokenSigningKey :one
INSERT INTO "token_signing_keys" (
    "kid",
    "key_type",
    "public_key",
    "private_key",
    "dek_kid",
    "crypto_suite",
    "expires_at",
    "usage",
    "is_distributed"
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
) RETURNING "id";

-- name: FindGlobalTokenSigningKey :one
SELECT * FROM "token_signing_keys"
WHERE 
    "key_type" = $1 AND 
    "usage" = 'global' AND
    "is_revoked" = false AND
    "expires_at" > $2
ORDER BY "id" DESC
LIMIT 1;

-- name: FindGlobalDistributedTokenSigningKeyPublicKeys :many
SELECT "public_key" FROM "token_signing_keys"
WHERE
    "usage" = 'global' AND
    "is_distributed" = true AND
    "is_revoked" = false AND
    "expires_at" > NOW()
ORDER BY "id" DESC;

-- name: FindTokenSigningKeyByKID :one
SELECT * FROM "token_signing_keys"
WHERE 
    "kid" = $1 AND
    "is_revoked" = false
LIMIT 1;


-- name: UpdateTokenSigningKeyDEKAndPrivateKey :exec
UPDATE "token_signing_keys"
SET
    "dek_kid"    = $2,
    "private_key" = $3,
    "updated_at" = NOW()
WHERE "id" = $1
RETURNING *;
