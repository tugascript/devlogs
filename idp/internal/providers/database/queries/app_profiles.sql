-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppProfile :exec
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id",
    "profile_type"
) VALUES (
    $1,
    $2,
    $3,
    $4
);

-- name: FindAppProfileByAppIDAndUserID :one
SELECT * FROM "app_profiles"
WHERE "app_id" = $1 AND "user_id" = $2;