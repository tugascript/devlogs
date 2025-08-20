-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountDynamicRegistrationConfig :one
INSERT INTO "account_dynamic_registration_configs" (
    "account_id",
    "account_public_id",
    "account_credentials_types",
    "whitelisted_domains",
    "require_software_statement_credential_types",
    "software_statement_verification_methods",
    "require_initial_access_token_credential_types",
    "initial_access_token_generation_methods"
) VALUES (
    $1, 
    $2, 
    $3, 
    $4, 
    $5, 
    $6, 
    $7,
    $8
) RETURNING *;

-- name: UpdateAccountDynamicRegistrationConfig :one
UPDATE "account_dynamic_registration_configs" SET
    "account_credentials_types" = $2,
    "whitelisted_domains" = $3,
    "require_software_statement_credential_types" = $4,
    "software_statement_verification_methods" = $5,
    "require_initial_access_token_credential_types" = $6,
    "initial_access_token_generation_methods" = $7
WHERE "id" = $1 
RETURNING *;

-- name: FindAccountDynamicRegistrationConfigByAccountID :one
SELECT * FROM "account_dynamic_registration_configs" 
WHERE "account_id" = $1 LIMIT 1;

-- name: FindAccountDynamicRegistrationConfigByAccountPublicID :one
SELECT * FROM "account_dynamic_registration_configs"
WHERE "account_public_id" = $1 LIMIT 1;

-- name: DeleteAccountDynamicRegistrationConfig :exec
DELETE FROM "account_dynamic_registration_configs" WHERE "id" = $1;