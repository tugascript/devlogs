-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountDynamicRegistrationDomainCode :exec
INSERT INTO "account_dynamic_registration_domain_codes" (
    "account_id",
    "account_dynamic_registration_domain_id",
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
    $6,
    $7
);