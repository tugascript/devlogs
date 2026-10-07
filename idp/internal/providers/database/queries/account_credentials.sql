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
    $39
) RETURNING *;

-- name: UpdateRegisteredAccountCredentials :one
UPDATE "account_credentials" SET
    "domain" = $2,
    "redirect_uris" = $3,
    "token_endpoint_auth_method" = $4,
    "grant_types" = $5,
    "response_types" = $6,
    "client_name" = $7,
    "client_uri" = $8,
    "logo_uri" = $9,
    "scopes" = $10,
    "contacts" = $11,
    "tos_uri" = $12,
    "policy_uri" = $13,
    "jwks_uri" = $14,
    "jwks" = $15,
    "software_id" = $16,
    "software_version" = $17,
    "sector_identifier_uri" = $18,
    "subject_type" = $19,
    "id_token_signed_response_alg" = $20,
    "id_token_encrypted_response_alg" = $21,
    "id_token_encrypted_response_enc" = $22,
    "userinfo_signed_response_alg" = $23,
    "userinfo_encrypted_response_alg" = $24,
    "userinfo_encrypted_response_enc" = $25,
    "request_object_signing_alg" = $26,
    "request_object_encryption_alg" = $27,
    "request_object_encryption_enc" = $28,
    "token_endpoint_auth_signing_alg" = $29,
    "default_max_age" = $30,
    "require_auth_time" = $31,
    "default_acr_values" = $32,
    "initiate_login_uri" = $33,
    "request_uris" = $34,
    "access_token_signing_alg" = $35,
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

-- name: LockRegisteredAccountCredentials :one
SELECT * FROM account_credentials WHERE client_id = $1 AND account_public_id = $2 FOR UPDATE;

-- name: SetAccountCredentialsRegistrationState :exec
UPDATE account_credentials SET registration_token_jti = $2, software_statement = $3 WHERE id = $1;

-- name: RevokeRegisteredAccountCredentialsSecrets :exec
UPDATE credentials_secrets SET is_revoked = true, updated_at = now()
WHERE id IN (SELECT credentials_secret_id FROM account_credentials_secrets WHERE account_credentials_id = $1);

-- name: RevokeRegisteredAccountCredentialsKeys :exec
UPDATE credentials_keys SET is_revoked = true, updated_at = now()
WHERE id IN (SELECT credentials_key_id FROM account_credentials_keys WHERE account_credentials_id = $1);

-- name: DeleteRegisteredAccountCredentialsGrants :exec
DELETE FROM grants WHERE account_id = $1 AND granted_client_id = $2;
