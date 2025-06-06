-- Copyright (c) 2025 Afonso Barracha
--
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

-- name: CreateExternalAuthProvider :one
INSERT INTO external_auth_providers (
  name,
  provider,
  icon,
  account_id,
  client_id,
  client_secret,
  scopes,
  auth_url,
  token_url,
  user_info_url,
  email_key,
  user_schema,
  user_mapping
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5,
  $6,
  $7,
  $8,
  $9,
  $10,
  $11,
  $12,
  $13
) RETURNING *;

-- name: FindExternalAuthProviderByID :one
SELECT * FROM "external_auth_providers"
WHERE id = $1 LIMIT 1;

-- name: FindExternalAuthProviderByProviderAndAccountID :one
SELECT * FROM "external_auth_providers"
WHERE
  provider = $1 AND
  account_id = $2
LIMIT 1;