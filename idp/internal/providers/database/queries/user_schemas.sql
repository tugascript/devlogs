-- name: CountUserSchemasByAccountID :one
SELECT COUNT("id") FROM "user_schemas"
WHERE "account_id" = $1;

-- name: CreateUserSchema :one
INSERT INTO "user_schemas" (
    "account_id",
    "schema_data"
) VALUES (
    $1,
    $2
) RETURNING *;

-- name: CreateDefaultUserSchema :one
INSERT INTO "user_schemas" (
    "account_id"
) VALUES (
    $1
) RETURNING *;

-- name: FindUserSchemaByAccountID :one
SELECT * FROM "user_schemas"
WHERE "account_id" = $1
LIMIT 1;

-- name: UpdateUserSchema :one
UPDATE "user_schemas" SET
    "schema_data" = $1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;
