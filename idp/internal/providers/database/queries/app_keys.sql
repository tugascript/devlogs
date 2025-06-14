-- name: CreateAppKey :exec
INSERT INTO "app_keys" (
    "app_id",
    "credentials_key_id",
    "account_id"
) VALUES (
    $1,
    $2,
    $3
);
