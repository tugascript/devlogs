-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateUserWithoutPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "user_data"
) VALUES (
    $1,
    $2,
    $3
) RETURNING *;

-- name: CountUsersByAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "account_id" = $1
LIMIT 1;

-- name: CreateUserWithPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "password",
    "user_data"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;
