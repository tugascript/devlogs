-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountTokenSigningKey :exec
INSERT INTO "account_token_signing_keys" (
    "account_id",
    "token_signing_key_id"
) VALUES (
    $1,
    $2
);

-- name: FindAccountTokenSigningKeyByAccountID :one
SELECT "t".* FROM "token_signing_keys" AS "t"
LEFT JOIN "account_token_signing_keys" AS "atsk" ON "t"."id" = "atsk"."token_signing_key_id"
WHERE "atsk"."account_id" = $1 AND "t"."key_type" = $2
LIMIT 1;

-- name: FindAccountTokenSigningKeyByAccountIDAndKID :one
SELECT "t".* FROM "token_signing_keys" AS "t"
LEFT JOIN "account_token_signing_keys" AS "atsk" ON "t"."id" = "atsk"."token_signing_key_id"
WHERE "atsk"."account_id" = $1 AND "t"."kid" = $2
LIMIT 1;

-- name: FindAccountDistributedTokenSigningKeyPublicKeysByAccountID :many
SELECT "t"."public_key" FROM "token_signing_keys" AS "t"
LEFT JOIN "account_token_signing_keys" AS "atsk" ON "t"."id" = "atsk"."token_signing_key_id"
WHERE "atsk"."account_id" = $1 AND
      "t"."is_distributed" = true AND
      "t"."is_revoked" = false AND
      "t"."expires_at" > NOW()
ORDER BY "t"."id" DESC;
