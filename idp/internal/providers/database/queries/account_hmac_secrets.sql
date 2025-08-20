-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountHMACSecret :one
INSERT INTO "account_hmac_secrets" (
    "account_id",
    "secret_id",
    "secret",
    "dek_kid",
    "expires_at"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING "id";

-- name: UpdateAccountHMACSecret :exec
UPDATE "account_hmac_secrets" SET
    "secret" = $2,
    "dek_kid" = $3,
    "updated_at" = now()
WHERE "id" = $1;

-- name: FindAccountHMACSecretByAccountIDAndSecretID :one
SELECT * FROM "account_hmac_secrets"
WHERE "account_id" = $1 AND "secret_id" = $2
LIMIT 1;

-- name: FindValidHMACSecretByAccountID :one
SELECT * FROM "account_hmac_secrets"
WHERE
    "account_id" = $1 AND
    "is_revoked" = false AND
    "expires_at" > now()
LIMIT 1;