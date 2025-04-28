-- name: CreateUserWithoutPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "user_data"
) VALUES (
    $1,
    $2,
    $3
) RETURNING *;

-- name: CountUsersByAccountID :one
SELECT COUNT("id") FROM "users"
WHERE "account_id" = $1
LIMIT 1;

-- name: CreateUserWithPassword :one
INSERT INTO "users" (
    "account_id",
    "email",
    "password",
    "user_data"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;
