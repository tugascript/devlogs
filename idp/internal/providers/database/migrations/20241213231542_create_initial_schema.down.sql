-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

DROP TABLE IF EXISTS "revoked_tokens";
DROP TABLE IF EXISTS "app_profiles";
DROP TABLE IF EXISTS "app_designs";
DROP TABLE IF EXISTS "app_service_audiences";
DROP TABLE IF EXISTS "app_server_urls";
DROP TABLE IF EXISTS "app_callback_uris";
DROP TABLE IF EXISTS "app_keys";
DROP TABLE IF EXISTS "app_secrets";
DROP TABLE IF EXISTS "apps";
DROP TABLE IF EXISTS "user_credentials_keys";
DROP TABLE IF EXISTS "user_credentials_secrets";
DROP TABLE IF EXISTS "user_credentials";
DROP TABLE IF EXISTS "user_auth_providers";
DROP TABLE IF EXISTS "user_totps";
DROP TABLE IF EXISTS "users";
DROP TABLE IF EXISTS "account_keys";
DROP TABLE IF EXISTS "oidc_configs";
DROP TABLE IF EXISTS "account_auth_providers";
DROP TABLE IF EXISTS "account_credentials_keys";
DROP TABLE IF EXISTS "account_credentials_secrets";
DROP TABLE IF EXISTS "account_credentials";
DROP TABLE IF EXISTS "account_totps";
DROP TABLE IF EXISTS "credentials_keys";
DROP TABLE IF EXISTS "credentials_secrets";
DROP TABLE IF EXISTS "accounts";
DROP TYPE IF EXISTS "two_factor_type";
DROP TYPE IF EXISTS "token_crypto_suite";
DROP TYPE IF EXISTS "auth_method";
DROP TYPE IF EXISTS "account_credentials_scope";
DROP TYPE IF EXISTS "auth_provider";
DROP TYPE IF EXISTS "claims";
DROP TYPE IF EXISTS "scopes";
DROP TYPE IF EXISTS "app_type";
DROP TYPE IF EXISTS "app_username_column";
DROP TYPE IF EXISTS "grant_type";
DROP TYPE IF EXISTS "response_type";