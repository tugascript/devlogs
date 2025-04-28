-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountTotps :exec
INSERT INTO "account_totps" (
  "account_id",
  "url",
  "secret",
  "dek",
  "recovery_codes"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
);

-- name: FindAccountTotpByAccountID :one
SELECT * FROM "account_totps"
WHERE "account_id" = $1 LIMIT 1;

-- name: UpdateAccountTotpByAccountID :exec
UPDATE "account_totps" SET
    "dek" = $1
WHERE "account_id" = $2;

-- name: DeleteAccountRecoveryKeys :exec
DELETE FROM "account_totps"
WHERE "account_id" = $1;