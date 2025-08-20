-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateDynamicRegistrationDomainCode :one
INSERT INTO "dynamic_registration_domain_codes" (
    "account_id",
    "verification_host",
    "verification_code",
    "verification_prefix",
    "hmac_secret_id",
    "expires_at"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING "id";

-- name: UpdateDynamicRegistrationDomainCode :exec
UPDATE "dynamic_registration_domain_codes" SET
    "verification_host" = $2,
    "verification_code" = $3,
    "verification_prefix" = $4,
    "hmac_secret_id" = $5,
    "expires_at" = $6
WHERE "id" = $1;

-- name: DeleteDynamicRegistrationDomainCode :exec
DELETE FROM "dynamic_registration_domain_codes"
WHERE "id" = $1;
