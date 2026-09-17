-- Copyright (c) 2026 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateGrant :one
INSERT INTO "grants" (
  "account_id",
  "grant_id",
  "granted_client_id",
  "granted_scopes",
  "granted_custom_scopes"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
) RETURNING id;
