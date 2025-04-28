-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAuthProvider :exec
INSERT INTO "auth_providers" (
  "email",
  "provider"
) VALUES (
  $1,
  $2
);

-- name: FindAuthProviderByEmailAndProvider :one
SELECT * FROM "auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" = $2
LIMIT 1;

-- name: DeleteExternalAuthProviders :exec
DELETE FROM "auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" != $2;
