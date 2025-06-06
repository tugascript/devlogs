-- name: CreateAppProfile :one
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id"
) VALUES (
    $1,
    $2,
    $3
) RETURNING *;

-- name: CreateAppProfileWithRoles :one
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id",
    "user_roles"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: FindAppProfileByAppIDAndUserID :one
SELECT * FROM "app_profiles"
WHERE "app_id" = $1 AND "user_id" = $2 LIMIT 1;