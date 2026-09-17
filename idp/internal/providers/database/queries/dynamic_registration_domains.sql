-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateDynamicRegistrationDomain :one
INSERT INTO "dynamic_registration_domains" (
    "account_id",
    "account_public_id",
    "domain",
    "verification_method",
    "usages"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;

-- name: FindDynamicRegistrationDomainByAccountPublicIDAndDomain :one
SELECT * FROM "dynamic_registration_domains" WHERE "account_public_id" = $1 AND "domain" = $2 LIMIT 1;

-- name: VerifyDynamicRegistrationDomain :one
UPDATE "dynamic_registration_domains"
SET
    "verified_at" = NOW(),
    "verification_method" = $2
WHERE "id" = $1 RETURNING *;

-- name: FindPaginatedDynamicRegistrationDomainsByAccountPublicIDOrderedByID :many
SELECT * FROM "dynamic_registration_domains"
WHERE "account_public_id" = $1
ORDER BY "id" DESC
LIMIT $2 OFFSET $3;

-- name: FindPaginatedDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain :many
SELECT * FROM "dynamic_registration_domains"
WHERE "account_public_id" = $1
ORDER BY "domain" ASC
LIMIT $2 OFFSET $3;

-- name: CountDynamicRegistrationDomainsByAccountPublicID :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE "account_public_id" = $1;

-- name: FilterDynamicRegistrationDomainsByAccountPublicIDOrderedByID :many
SELECT * FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
ORDER BY "id" DESC
LIMIT $3 OFFSET $4;

-- name: FilterDynamicRegistrationDomainsByAccountPublicIDOrderedByDomain :many
SELECT * FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
ORDER BY "domain" ASC
LIMIT $3 OFFSET $4;

-- name: CountFilteredDynamicRegistrationDomainsByAccountPublicID :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" ILIKE $2
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomain :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE "domain" = $1 AND "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomain :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE "domain" = $1
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomains :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE "domain" IN (sqlc.slice('domains')) AND "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomains :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE "domain" IN (sqlc.slice('domains'))
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomainsAndAccountPublicID :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" IN (sqlc.slice('domains')) AND
    "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomainsAccountPublicIDAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "usages" @> $2 AND
    "domain" IN (sqlc.slice('domains')) AND
    "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomainAndAccountPublicID :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" = $2 AND
    "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountVerifiedDynamicRegistrationDomainsByDomainAccountPublicIDAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" = $2 AND
    "usages" && sqlc.arg(usages)::dynamic_registration_usage[] AND
    "verified_at" IS NOT NULL
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomainsAccountPublicIDAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "usages" && sqlc.arg(usages)::dynamic_registration_usage[] AND
    "domain" IN (sqlc.slice('domains'))
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomainAndAccountPublicIDAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "account_public_id" = $1 AND
    "domain" = $2 AND
    "usages" && sqlc.arg(usages)::dynamic_registration_usage[]
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomainAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "domain" = $1 AND
    "usages" && sqlc.arg(usages)::dynamic_registration_usage[]
LIMIT 1;

-- name: CountDynamicRegistrationDomainsByDomainsAndUsages :one
SELECT COUNT(*) FROM "dynamic_registration_domains"
WHERE
    "domain" IN (sqlc.slice('domains')) AND
    "usages" && sqlc.arg(usages)::dynamic_registration_usage[]
LIMIT 1;

-- name: DeleteDynamicRegistrationDomain :exec
DELETE FROM "dynamic_registration_domains"
WHERE "id" = $1;
