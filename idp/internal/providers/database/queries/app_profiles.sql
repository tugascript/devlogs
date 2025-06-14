-- name: CreateAppProfile :exec
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: FindAppProfileByAppIDAndUserID :one
SELECT * FROM "app_profiles"
WHERE "app_id" = $1 AND "user_id" = $2 LIMIT 1;