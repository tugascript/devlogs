-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountCredentialSecret :exec
INSERT INTO "account_credentials_secrets" (
    "account_credentials_id",
    "credentials_secret_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: FindPaginatedAccountCredentialSecretsByAccountCredentialID :many
SELECT "csr".* FROM "credentials_secrets" "csr"
LEFT JOIN "account_credentials_secrets" "acs" ON "acs"."credentials_secret_id" = "csr"."id"
WHERE "acs"."account_credentials_id" = $1
ORDER BY "csr"."expires_at" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialSecretsByAccountCredentialID :one
SELECT COUNT("csr"."id") FROM "credentials_secrets" "csr"
LEFT JOIN "account_credentials_secrets" "acs" ON "acs"."credentials_secret_id" = "csr"."id"
WHERE "acs"."account_credentials_id" = $1
LIMIT 1;

-- name: FindCurrentAccountCredentialSecretByAccountCredentialID :one
SELECT "csr".* FROM "credentials_secrets" "csr"
LEFT JOIN "account_credentials_secrets" "acs" ON "acs"."credentials_secret_id" = "csr"."id"
WHERE 
    "acs"."account_credentials_id" = $1 AND 
    "csr"."is_revoked" = false AND 
    "csr"."expires_at" > now()
LIMIT 1;

-- name: FindAccountCredentialSecretByAccountCredentialIDAndCredentialsSecretID :one
SELECT "csr".* FROM "credentials_secrets" "csr"
LEFT JOIN "account_credentials_secrets" "acs" ON "acs"."credentials_secret_id" = "csr"."id"
WHERE 
    "acs"."account_credentials_id" = $1 AND 
    "csr"."secret_id" = $2
LIMIT 1;

-- name: RevokeAccountCredentialSecret :exec
UPDATE "credentials_secrets" SET
    "is_revoked" = true
WHERE "id" = $1;