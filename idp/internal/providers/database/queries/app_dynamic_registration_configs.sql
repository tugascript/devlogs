-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppDynamicRegistrationConfig :one
INSERT INTO "app_dynamic_registration_configs" (
    "account_id",
    "account_public_id",
    "allowed_app_types",
    "default_allow_user_registration",
    "default_auth_providers",
    "default_username_column",
    "default_allowed_scopes",
    "default_scopes",
    "require_verified_domains_app_types",
    "require_software_statement_app_types",
    "software_statement_verification_methods",
    "require_initial_access_token_app_types",
    "initial_access_token_generation_methods",
    "initial_access_token_ttl",
    "initial_access_token_max_uses",
    "allowed_grant_types",
    "allowed_response_types",
    "allowed_token_endpoint_auth_methods",
    "max_redirect_uris"
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
    $19
) RETURNING *;

-- name: UpdateAppDynamicRegistrationConfig :one
UPDATE "app_dynamic_registration_configs" SET
    "allowed_app_types" = $2,
    "default_allow_user_registration" = $3,
    "default_auth_providers" = $4,
    "default_username_column" = $5,
    "default_allowed_scopes" = $6,
    "default_scopes" = $7,
    "require_verified_domains_app_types" = $8,
    "require_software_statement_app_types" = $9,
    "software_statement_verification_methods" = $10,
    "require_initial_access_token_app_types" = $11,
    "initial_access_token_generation_methods" = $12,
    "initial_access_token_ttl" = $13,
    "initial_access_token_max_uses" = $14,
    "allowed_grant_types" = $15,
    "allowed_response_types" = $16,
    "allowed_token_endpoint_auth_methods" = $17,
    "max_redirect_uris" = $18
WHERE "id" = $1 
RETURNING *;

-- name: FindAppDynamicRegistrationConfigByAccountPublicID :one
SELECT * FROM "app_dynamic_registration_configs" 
WHERE "account_public_id" = $1 LIMIT 1;

-- name: FindAppDynamicRegistrationConfigByAccountID :one
SELECT * FROM "app_dynamic_registration_configs" 
WHERE "account_id" = $1 LIMIT 1;

-- name: DeleteAppDynamicRegistrationConfig :exec
DELETE FROM "app_dynamic_registration_configs" WHERE "id" = $1;

