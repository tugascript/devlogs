-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountDataEncryptionKey :exec
INSERT INTO "account_data_encryption_keys" (
    "account_id",
    "data_encryption_key_id"
) VALUES (
    $1,
    $2
);

-- name: FindAccountDataEncryptionKeyByAccountID :one
SELECT "d".* FROM "data_encryption_keys" AS "d"
LEFT JOIN "account_data_encryption_keys" AS "adek" ON "d"."id" = "adek"."data_encryption_key_id"
WHERE "adek"."account_id" = $1 AND "d"."expires_at" > $2
LIMIT 1;

-- name: FindAccountDataEncryptionKeyByAccountIDAndKID :one
SELECT "d".* FROM "data_encryption_keys" AS "d"
LEFT JOIN "account_data_encryption_keys" AS "adek" ON "d"."id" = "adek"."data_encryption_key_id"
WHERE "adek"."account_id" = $1 AND "d"."kid" = $2
LIMIT 1;
