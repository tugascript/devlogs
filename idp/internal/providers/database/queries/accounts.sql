-- name: CreateAccountWithPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "email", 
    "password"
) VALUES (
    $1, 
    $2, 
    $3, 
    $4
) RETURNING *;

-- name: CreateAccountWithoutPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "email",
    "is_confirmed"
) VALUES (
    $1, 
    $2, 
    $3,
    true
) RETURNING *;

-- name: UpdateAccountEmail :one
UPDATE "accounts" SET
    "email" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: UpdateAccountPassword :one
UPDATE "accounts" SET
    "password" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: FindAccountByEmail :one
SELECT * FROM "accounts"
WHERE "email" = $1 LIMIT 1;

-- name: FindAccountById :one
SELECT * FROM "accounts"
WHERE "id" = $1 LIMIT 1;

-- name: ConfirmAccount :one
UPDATE "accounts" SET
    "is_confirmed" = true,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;
