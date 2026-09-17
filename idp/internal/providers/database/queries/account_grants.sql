-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountGrantWithoutAccountCredentials :exec
INSERT INTO "account_grants" (
  "account_id",
  "account_version",
  "grant_id",
  "granted_client_id"
) VALUES (
  $1,
  $2,
  $3,
  $4
);

-- name: CreateAccountGrantWithAccountCredentials :exec
INSERT INTO "account_grants" (
  "account_id",
  "account_version",
  "grant_id",
  "granted_client_id",
  "account_credentials_id"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
);

-- name: FindAccountGrantByAccountIDAndGrantedClientID :one
SELECT "a".*, "g".*
FROM "account_grants" AS "a"
LEFT JOIN "grants" AS "g" ON "a"."grant_id" = "g"."id"
WHERE "a"."account_id" = $1
AND "a"."granted_client_id" = $2
LIMIT 1;
