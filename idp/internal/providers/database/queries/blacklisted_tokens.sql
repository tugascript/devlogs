-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: BlacklistToken :exec
INSERT INTO "blacklisted_tokens" (
  "id",
  "expires_at"
) VALUES (
  $1,
    $2
);

-- name: GetBlacklistedToken :one
SELECT * FROM "blacklisted_tokens"
WHERE "id" = $1 LIMIT 1;