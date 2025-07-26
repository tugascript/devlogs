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

-- name: FindRelatedAppsByAppID :many
SELECT a.* FROM "apps" a
INNER JOIN "app_related_apps" ara ON a.id = ara.related_app_id
WHERE ara.app_id = $1
ORDER BY a.name ASC;

-- name: DeleteAppRelatedAppsByAppIDAndRelatedAppIDs :exec
DELETE FROM "app_related_apps"
WHERE "app_id" = $1 AND "related_app_id" IN (sqlc.slice('related_app_ids'));