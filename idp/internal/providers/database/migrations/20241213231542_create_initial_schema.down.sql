-- Copyright (c) 2025 Afonso Barracha
-- 
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at https://mozilla.org/MPL/2.0/.

DROP TABLE IF EXISTS "revoked_tokens";
DROP TABLE IF EXISTS "app_profiles";
DROP TABLE IF EXISTS "dynamic_registration_configs";
DROP TABLE IF EXISTS "app_designs";
DROP TABLE IF EXISTS "app_service_configs";
DROP TABLE IF EXISTS "app_related_apps";
DROP TABLE IF EXISTS "app_keys";
DROP TABLE IF EXISTS "app_secrets";
DROP TABLE IF EXISTS "apps";
DROP TABLE IF EXISTS "user_credentials_keys";
DROP TABLE IF EXISTS "user_credentials_secrets";
DROP TABLE IF EXISTS "user_credentials";
DROP TABLE IF EXISTS "user_auth_providers";
DROP TABLE IF EXISTS "user_totps";
DROP TABLE IF EXISTS "user_data_encryption_keys";
DROP TABLE IF EXISTS "users";
DROP TABLE IF EXISTS "account_token_signing_keys";
DROP TABLE IF EXISTS "oidc_configs";
DROP TABLE IF EXISTS "account_auth_providers";
DROP TABLE IF EXISTS "account_credentials_keys";
DROP TABLE IF EXISTS "account_credentials_secrets";
DROP TABLE IF EXISTS "account_credentials_mcps";
DROP TABLE IF EXISTS "account_credentials";
DROP TABLE IF EXISTS "account_totps";
DROP TABLE IF EXISTS "account_data_encryption_keys";
DROP TABLE IF EXISTS "account_key_encryption_keys";
DROP TABLE IF EXISTS "credentials_keys";
DROP TABLE IF EXISTS "credentials_secrets";
DROP TABLE IF EXISTS "totps";
DROP TABLE IF EXISTS "accounts";
DROP TABLE IF EXISTS "token_signing_keys";
DROP TABLE IF EXISTS "data_encryption_keys";
DROP TABLE IF EXISTS "key_encryption_keys";
DROP TYPE IF EXISTS "kek_usage";
DROP TYPE IF EXISTS "dek_usage";
DROP TYPE IF EXISTS "token_crypto_suite";
DROP TYPE IF EXISTS "token_key_usage";
DROP TYPE IF EXISTS "token_key_type";
DROP TYPE IF EXISTS "two_factor_type";
DROP TYPE IF EXISTS "totp_usage";
DROP TYPE IF EXISTS "credentials_usage";
DROP TYPE IF EXISTS "secret_storage_mode";
DROP TYPE IF EXISTS "auth_method";
DROP TYPE IF EXISTS "response_type";
DROP TYPE IF EXISTS "account_credentials_scope";
DROP TYPE IF EXISTS "account_credentials_type";
DROP TYPE IF EXISTS "transport";
DROP TYPE IF EXISTS "creation_source";
DROP TYPE IF EXISTS "auth_provider";
DROP TYPE IF EXISTS "claims";
DROP TYPE IF EXISTS "scopes";
DROP TYPE IF EXISTS "app_type";
DROP TYPE IF EXISTS "app_username_column";
DROP TYPE IF EXISTS "grant_type";
DROP TYPE IF EXISTS "initial_access_token_generation_method";
DROP TYPE IF EXISTS "software_statement_verification_method";
DROP TYPE IF EXISTS "app_profile_type";
DROP TYPE IF EXISTS "token_owner";
