-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateUserAuthProvider :exec
INSERT INTO "user_auth_providers" (
  "account_id",
  "user_id",
  "provider"
) VALUES (
  $1,
  $2,
  $3
);

-- name: FindUserAuthProviderByUserIDAndProvider :one
SELECT * FROM "user_auth_providers"
WHERE
  "user_id" = $1 AND
  "provider" = $2
LIMIT 1;
