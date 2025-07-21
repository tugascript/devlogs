-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppAuthCodeConfig :one
INSERT INTO "app_auth_code_configs" (
    "account_id",
    "app_id",
    "callback_uris",
    "logout_uris",
    "allowed_origins",
    "code_challenge_method"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6
) RETURNING *;