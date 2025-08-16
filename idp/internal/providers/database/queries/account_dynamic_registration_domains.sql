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