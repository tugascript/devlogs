-- name: DeleteDistributedAppKeysByAppID :exec
DELETE FROM "app_keys"
WHERE "app_id" = $1 AND "is_distributed" = true;

-- name: CreateAppKey :one
INSERT INTO "app_keys" (
    "app_id",
    "account_id",
    "name",
    "jwt_crypto_suite",
    "public_kid",
    "public_key",
    "private_key",
    "is_distributed"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8
) RETURNING *;

-- name: FindAppKeyByAppIDAndName :one
SELECT * FROM "app_keys"
WHERE "app_id" = $1 AND "name" = $2
LIMIT 1;
