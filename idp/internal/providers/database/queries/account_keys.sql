-- name: FindAccountKeysByClientID :one
SELECT * FROM "account_keys"
WHERE "client_id" = $1
LIMIT 1;

-- name: CreateAccountKeys :one
INSERT INTO "account_keys" (
    "client_id",
    "client_secret",
    "account_id",
    "scopes"
) VALUES (
    $1,
    $2,
    $3,
    $4
) RETURNING *;

-- name: UpdateAccountKeysClientSecret :one
UPDATE "account_keys" SET
    "client_secret" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING *;

-- name: UpdateAccountKeysScope :one
UPDATE "account_keys" SET
    "scopes" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING *;

-- name: DeleteAccountKeys :exec
DELETE FROM "account_keys"
WHERE "client_id" = $1;

-- name: FindPaginatedAccountKeysByAccountID :many
SELECT * FROM "account_keys"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountKeysByAccountID :one
SELECT COUNT("id") FROM "account_keys"
WHERE "account_id" = $1
LIMIT 1;