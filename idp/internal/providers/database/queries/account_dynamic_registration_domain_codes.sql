-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountDynamicRegistrationDomainCode :exec
INSERT INTO "account_dynamic_registration_domain_codes" (
    "account_dynamic_registration_domain_id",
    "dynamic_registration_domain_code_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: FindDynamicRegistrationDomainCodeByAccountDynamicRegistrationDomainID :one
SELECT "d".* FROM "dynamic_registration_domain_codes" "d"
LEFT JOIN "account_dynamic_registration_domain_codes" "a" ON "d"."id" = "a"."dynamic_registration_domain_code_id"
WHERE "a"."account_dynamic_registration_domain_id" = $1
LIMIT 1;
