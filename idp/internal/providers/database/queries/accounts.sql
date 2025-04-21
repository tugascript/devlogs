-- name: CreateAccountWithPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "username",
    "email", 
    "password"
) VALUES (
    $1, 
    $2, 
    $3,
    $4,
    $5
) RETURNING *;

-- name: CreateAccountWithoutPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "username",
    "email",
    "version",
    "is_confirmed"
) VALUES (
    $1, 
    $2, 
    $3,
    $4,
    1,
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

-- name: CountAccountAlikeUsernames :one
SELECT COUNT("id") FROM "accounts"
WHERE "username" ILIKE $1 LIMIT 1;

-- name: ConfirmAccount :one
UPDATE "accounts" SET
    "is_confirmed" = true,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING *;

-- name: UpdateAccountTwoFactorType :one
UPDATE "accounts" SET
    "two_factor_type" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING *;

-- name: DeleteAllAccounts :exec
DELETE FROM "accounts";

-- name: DeleteAccount :exec
DELETE FROM "accounts"
WHERE "id" = $1;
