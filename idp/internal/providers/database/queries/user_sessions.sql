-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: FindUserSessionByUserIDAndSessionUUID :one
SELECT "u".*, "s".*
FROM "user_sessions" AS "u"
LEFT JOIN "sessions" AS "s" ON "u"."session_id" = "s"."id"
WHERE "u"."user_id" = $1
AND "u"."session_uuid" = $2
LIMIT 1;
