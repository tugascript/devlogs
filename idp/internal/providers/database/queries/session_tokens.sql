-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateSessionToken :exec
INSERT INTO "session_tokens" (
  "token_id",
  "account_id",
  "session_id",
  "session_uuid",
  "grant_id",
  "expires_at"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6
);

-- name: FindSessionTokenByTokenID :one
SELECT * FROM "session_tokens"
WHERE "token_id" = $1 LIMIT 1;

-- name: DeleteSessionToken :exec
DELETE FROM "session_tokens"
WHERE "token_id" = $1;
