-- name: CreateAppProfileWithoutData :exec
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id"
) VALUES (
    $1,
    $2,
    $3
);

-- name: CreateAppProfileWithData :exec
INSERT INTO "app_profiles" (
    "account_id",
    "user_id",
    "app_id",
    "profile_data"
) VALUES (
    $1,
    $2,
    $3,
    $4
);

-- name: FindAppProfileByAppIDAndUserID :one
SELECT * FROM "app_profiles"
WHERE "app_id" = $1 AND "user_id" = $2 LIMIT 1;