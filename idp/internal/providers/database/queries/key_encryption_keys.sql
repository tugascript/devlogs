-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateKeyEncryptionKey :one
INSERT INTO "key_encryption_keys" (
    "kid",
    "usage",
    "next_rotation_at"
) VALUES (
    $1,
    $2,
    $3
) RETURNING "id";

-- name: RotateKeyEncryptionKey :one
UPDATE "key_encryption_keys" SET
    "version" = "version" + 1,
    "next_rotation_at" = $2,
    "rotated_at" = now()
WHERE "id" = $1
RETURNING "id";

-- name: FindKeyEncryptionKeyByID :one
SELECT * FROM "key_encryption_keys"
WHERE "id" = $1
LIMIT 1;

-- name: FindKeyEncryptionKeyByKidAndUsage :one
SELECT * FROM "key_encryption_keys"
WHERE "kid" = $1 AND "usage" = $2
LIMIT 1;

-- name: FindGlobalKeyEncryptionKey :one
SELECT * FROM "key_encryption_keys"
WHERE "usage" = 'global'
LIMIT 1;