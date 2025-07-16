-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindUserTotpByUserID :one
SELECT "t".* FROM "totps" AS "t"
LEFT JOIN "user_totps" AS "at" ON "at"."totp_id" = "t"."id"
WHERE "at"."user_id" = $1 LIMIT 1;