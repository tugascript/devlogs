-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAccountTotp :exec
INSERT INTO "account_totps" (
  "account_id",
  "totp_id"
) VALUES (
  $1,
  $2
);

-- name: FindAccountTotpByAccountID :one
SELECT "t".* FROM "totps" AS "t"
LEFT JOIN "account_totps" AS "at" ON "at"."totp_id" = "t"."id"
WHERE
    "at"."account_id" = $1
LIMIT 1;

-- name: DeleteAccountRecoveryKeys :exec
DELETE FROM "account_totps"
WHERE "account_id" = $1;

-- -- name: UpdateAccountTotp :exec
-- UPDATE "account_totps" SET
--   "url" = $2,
--   "secret" = $3,
--   "dek_kid" = $4,
--   "recovery_codes" = $5
-- WHERE "id" = $1;