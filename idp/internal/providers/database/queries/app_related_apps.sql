-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateAppRelatedApp :exec
INSERT INTO "app_related_apps" (
    "app_id",
    "related_app_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);