-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindDynamicRegistrationSoftwareStatementKeysByRootDomainAndAccountPublicID :one
SELECT "c".* FROM "credentials_keys" AS "c"
LEFT JOIN "dynamic_registration_software_statement_keys" AS "d" ON "c"."id" = "d"."credential_key_id"
WHERE "d"."root_domain" = $1 AND "d"."account_public_id" = $2
LIMIT 1;

-- name: FindDynamicRegistrationSoftwareStatementKeysByCredentialsKeyKIDAndAccountPublicID :one
SELECT * FROM "dynamic_registration_software_statement_keys"
WHERE "credentials_key_kid" = $1 AND "account_public_id" = $2
LIMIT 1;
