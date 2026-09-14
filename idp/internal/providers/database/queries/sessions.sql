-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateSession :one
INSERT INTO "sessions" (
  "account_id",
  "grant_id",
  "session_id",
  "session_type",
  "session_client_id",
  "ip_address",
  "user_agent",
  "expires_at"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8
) RETURNING "id";

-- name: UpdateSessionExpiresAt :exec
UPDATE "sessions" SET "expires_at" = $1 WHERE "id" = $2;

-- name: DeleteSessionByID :exec
DELETE FROM "sessions" WHERE "id" = $1;
