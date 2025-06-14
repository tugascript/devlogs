-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountAuthProvider :exec
INSERT INTO "account_auth_providers" (
  "email",
  "provider"
) VALUES (
  $1,
  $2
);

-- name: FindAccountAuthProviderByEmailAndProvider :one
SELECT * FROM "account_auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" = $2
LIMIT 1;

-- name: DeleteExternalAccountAuthProviders :exec
DELETE FROM "account_auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" != "username_password";
