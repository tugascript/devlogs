-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountCredentialKey :exec
INSERT INTO "account_credentials_keys" (
    "account_credentials_id",
    "credentials_key_id",
    "account_id",
    "account_public_id",
    "jwk_kid"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
);

-- name: FindAccountCredentialsKeyAccountByAccountCredentialIDAndJWKKID :one
SELECT "a".* FROM "accounts" AS "a"
LEFT JOIN "account_credentials_keys" AS "ack" ON "ack"."account_id" = "a"."id"
WHERE
    "ack"."account_credentials_id" = $1 AND
    "ack"."jwk_kid" = $2
LIMIT 1;

-- name: FindPaginatedAccountCredentialKeysByAccountCredentialID :many
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "account_credentials_keys" "ack" ON "ack"."credentials_key_id" = "ckr"."id"
WHERE "ack"."account_credentials_id" = $1
ORDER BY "ckr"."expires_at" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialKeysByAccountCredentialID :one
SELECT COUNT("ckr"."id") FROM "credentials_keys" "ckr"
LEFT JOIN "account_credentials_keys" "ack" ON "ack"."credentials_key_id" = "ckr"."id"
WHERE "ack"."account_credentials_id" = $1
LIMIT 1;

-- name: FindCurrentAccountCredentialKeyByAccountCredentialID :one
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "account_credentials_keys" "ack" ON "ack"."credentials_key_id" = "ckr"."id"
WHERE 
    "ack"."account_credentials_id" = $1 AND 
    "ckr"."is_revoked" = false AND 
    "ckr"."expires_at" > now()
LIMIT 1;

-- name: FindAccountCredentialKeyByAccountCredentialIDAndPublicKID :one
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "account_credentials_keys" "ack" ON "ack"."credentials_key_id" = "ckr"."id"
WHERE 
    "ack"."account_credentials_id" = $1 AND 
    "ckr"."public_kid" = $2
LIMIT 1;

-- name: FindActiveAccountCredentialKeysByAccountPublicID :many
SELECT "ckr".* FROM "credentials_keys" "ckr"
LEFT JOIN "account_credentials_keys" "ack" ON "ack"."credentials_key_id" = "ckr"."id"
WHERE 
    "ack"."account_public_id" = $1 AND 
    "ckr"."is_revoked" = false AND 
    "ckr"."expires_at" > now()
ORDER BY "ckr"."expires_at" DESC;