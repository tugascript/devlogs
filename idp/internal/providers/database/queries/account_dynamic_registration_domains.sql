-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountDynamicRegistrationDomain :one
INSERT INTO "account_dynamic_registration_domains" (
    "account_id",
    "account_public_id",
    "domain",
    "verification_method"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: FindAccountDynamicRegistrationDomainByAccountPublicIDAndDomain :one
SELECT * FROM "account_dynamic_registration_domains" WHERE "account_public_id" = $1 AND "domain" = $2 LIMIT 1;

-- name: VerifyAccountDynamicRegistrationDomain :one
UPDATE "account_dynamic_registration_domains"
SET
    "verified_at" = NOW(),
    "verification_method" = $2
WHERE "id" = $1 RETURNING *;

-- name: FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByID :many
SELECT * FROM "account_dynamic_registration_domains"
WHERE "account_public_id" = $1
ORDER BY "id" DESC
LIMIT $2 OFFSET $3;

-- name: FindPaginatedAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain :many
SELECT * FROM "account_dynamic_registration_domains"
WHERE "account_public_id" = $1
ORDER BY "domain" ASC
LIMIT $2 OFFSET $3;

-- name: CountAccountDynamicRegistrationDomainsByAccountPublicID :one
SELECT COUNT(*) FROM "account_dynamic_registration_domains"
WHERE "account_public_id" = $1;

-- name: FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByID :many
SELECT * FROM "account_dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
ORDER BY "id" DESC
LIMIT $3 OFFSET $4;

-- name: FilterAccountDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain :many
SELECT * FROM "account_dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
ORDER BY "domain" ASC
LIMIT $3 OFFSET $4;

-- name: CountFilteredAccountDynamicRegistrationDomainsByAccountPublicID :one
SELECT COUNT(*) FROM "account_dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
LIMIT 1;

-- name: DeleteAccountDynamicRegistrationDomain :exec
DELETE FROM "account_dynamic_registration_domains"
WHERE "id" = $1;
