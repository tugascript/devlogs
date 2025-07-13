-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountKeyEncryptionKey :exec
INSERT INTO "account_key_encryption_keys" (
    "account_id", 
    "key_encryption_key_id"
) VALUES (
    $1, 
    $2
);

-- name: FindAccountKeyEncryptionKeyByAccountID :one
SELECT "k".* FROM "key_encryption_keys" AS "k"
LEFT JOIN "account_key_encryption_keys" AS "akek" ON "k"."id" = "akek"."key_encryption_key_id"
WHERE "akek"."account_id" = $1
LIMIT 1;
