-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppServiceConfig :one
INSERT INTO "app_service_configs" (
    "account_id",
    "app_id",
    "auth_methods",
    "grant_types",
    "allowed_domains"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING *;