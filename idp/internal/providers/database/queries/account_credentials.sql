-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindAccountCredentialsByClientID :one
SELECT * FROM "account_credentials"
WHERE "client_id" = $1
LIMIT 1;

-- name: FindAccountCredentialsByAccountPublicIDAndClientID :one
SELECT * FROM "account_credentials"
WHERE "account_public_id" = $1 AND "client_id" = $2
LIMIT 1;

-- name: CountAccountCredentialsByAccountPublicIDAndClientID :one
SELECT COUNT(*) FROM "account_credentials"
WHERE "account_public_id" = $1 AND "client_id" = $2
LIMIT 1;

-- name: CreateAccountCredentials :one
INSERT INTO "account_credentials" (
    "account_id",
    "account_public_id",
    "domain",
    "creation_method",
    "transport",
    "client_id",
    "redirect_uris",
    "token_endpoint_auth_method",
    "grant_types",
    "response_types",
    "client_name",
    "client_uri",
    "logo_uri",
    "scopes",
    "contacts",
    "tos_uri",
    "policy_uri",
    "jwks_uri",
    "jwks",
    "software_id",
    "software_version",
    "credentials_type",
    "sector_identifier_uri",
    "subject_type",
    "id_token_signed_response_alg",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "request_object_signing_alg",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "token_endpoint_auth_signing_alg",
    "default_max_age",
    "require_auth_time",
    "default_acr_values",
    "initiate_login_uri",
    "request_uris",
    "access_token_signing_alg"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20,
    $21,
    $22,
    $23,
    $24,
    $25,
    $26,
    $27,
    $28,
    $29,
    $30,
    $31,
    $32,
    $33,
    $34,
    $35,
    $36,
    $37,
    $38,
    $39,
    $40
) RETURNING *;

-- name: UpdateRegisteredAccountCredentials :one
UPDATE "account_credentials" SET
    "domain" = $2,
    "transport" = $3,
    "redirect_uris" = $4,
    "token_endpoint_auth_method" = $5,
    "grant_types" = $6,
    "response_types" = $7,
    "client_name" = $8,
    "client_uri" = $9,
    "logo_uri" = $10,
    "scopes" = $11,
    "contacts" = $12,
    "tos_uri" = $13,
    "policy_uri" = $14,
    "jwks_uri" = $15,
    "jwks" = $16,
    "software_id" = $17,
    "software_version" = $18,
    "sector_identifier_uri" = $19,
    "subject_type" = $20,
    "id_token_signed_response_alg" = $21,
    "id_token_encrypted_response_alg" = $22,
    "id_token_encrypted_response_enc" = $23,
    "userinfo_signed_response_alg" = $24,
    "userinfo_encrypted_response_alg" = $25,
    "userinfo_encrypted_response_enc" = $26,
    "request_object_signing_alg" = $27,
    "request_object_encryption_alg" = $28,
    "request_object_encryption_enc" = $29,
    "token_endpoint_auth_signing_alg" = $30,
    "default_max_age" = $31,
    "require_auth_time" = $32,
    "default_acr_values" = $33,
    "initiate_login_uri" = $34,
    "request_uris" = $35,
    "access_token_signing_alg" = $36,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateAccountCredentials :one
UPDATE "account_credentials" SET
    "scopes" = $2,
    "client_name" = $3,
    "domain" = $4,
    "client_uri" = $5,
    "redirect_uris" = $6,
    "logo_uri" = $7,
    "policy_uri" = $8,
    "tos_uri" = $9,
    "software_version" = $10,
    "contacts" = $11,
    "transport" = $12,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: CountAccountCredentialsByNameAndAccountID :one
SELECT COUNT(*) FROM "account_credentials"
WHERE "account_id" = $1 AND "client_name" = $2;

-- name: DeleteAccountCredentials :exec
DELETE FROM "account_credentials"
WHERE "client_id" = $1;

-- name: FindPaginatedAccountCredentialsByAccountPublicID :many
SELECT * FROM "account_credentials"
WHERE "account_public_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialsByAccountPublicID :one
SELECT COUNT(*) FROM "account_credentials"
WHERE "account_public_id" = $1
LIMIT 1;

-- name: DeleteAllAccountCredentials :exec
DELETE FROM "account_credentials";
