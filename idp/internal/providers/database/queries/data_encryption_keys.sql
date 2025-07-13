-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateDataEncryptionKey :one
INSERT INTO "data_encryption_keys" (
    "kid",
    "dek",
    "kek_kid",
    "usage",
    "expires_at"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: RevokeDataEncryptionKey :exec
UPDATE "data_encryption_keys" SET
    "is_revoked" = true
WHERE "id" = $1;

-- name: FindValidGlobalDataEncryptionKey :one
SELECT * FROM "data_encryption_keys"
WHERE
    "usage" = 'global' AND
    "is_revoked" = false AND
    "expires_at" > $1
ORDER BY "expires_at" DESC
LIMIT 1;

-- name: FindDataEncryptionKeyByKID :one
SELECT * FROM "data_encryption_keys"
WHERE "kid" = $1
LIMIT 1;