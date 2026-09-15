-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountSessionWithoutAccountCredentials :exec
INSERT INTO "account_sessions" (
  "account_id",
  "account_version",
  "session_id",
  "session_uuid"
) VALUES (
  $1,
  $2,
  $3,
  $4
);

-- name: CreateAccountSessionWithAccountCredentials :exec
INSERT INTO "account_sessions" (
  "account_id",
  "account_version",
  "session_id",
  "session_uuid",
  "account_credentials_id"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
);

-- name: FindAccountSessionByAccountIDAndSessionUUID :one
SELECT "a".*, "s".*
FROM "account_sessions" AS "a"
LEFT JOIN "sessions" AS "s" ON "a"."session_id" = "s"."id"
WHERE "a"."account_id" = $1
AND "a"."session_uuid" = $2
LIMIT 1;

-- name: DeleteAccountSessionByAccountIDAndSessionID :exec
DELETE FROM "account_sessions"
WHERE "account_id" = $1 AND "session_id" = $2;

-- name: DeleteAllSessionsByAccountID :exec
DELETE FROM "sessions" AS "s"
USING "account_sessions" AS "a"
WHERE "a"."session_id" = "s"."id"
AND "a"."account_id" = $1;
