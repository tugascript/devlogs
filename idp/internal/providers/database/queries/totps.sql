-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateTotp :one
INSERT INTO "totps" (
    "dek_kid",
    "url",
    "secret",
    "recovery_codes",
    "usage",
    "account_id"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING "id";

-- name: UpdateTOTP :exec
UPDATE "totps" SET
    "url" = $2,
    "secret" = $3,
    "dek_kid" = $4,
    "recovery_codes" = $5,
    "updated_at" = now()
WHERE "id" = $1;

-- name: UpdateTOTPSecretAndDEK :exec
UPDATE "totps" SET
    "secret" = $2,
    "dek_kid" = $3,
    "updated_at" = now()
WHERE "id" = $1;