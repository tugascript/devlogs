-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: RevokeToken :exec
INSERT INTO "revoked_tokens" (
  "token_id",
  "expires_at"
) VALUES (
  $1,
  $2
);

-- name: GetRevokedToken :one
SELECT * FROM "revoked_tokens"
WHERE "token_id" = $1 LIMIT 1;