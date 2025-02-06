-- name: FindAccountCredentialsByClientID :one
SELECT * FROM "account_credentials"
WHERE "client_id" = $1
LIMIT 1;

-- name: CreateAccountCredentials :one
INSERT INTO "account_credentials" (
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

-- name: UpdateAccountCredentialsClientSecret :one
UPDATE "account_credentials" SET
    "client_secret" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING *;

-- name: UpdateAccountCredentialsScope :one
UPDATE "account_credentials" SET
    "scopes" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING *;

-- name: DeleteAccountCredentials :exec
DELETE FROM "account_credentials"
WHERE "client_id" = $1;

-- name: FindPaginatedAccountCredentialsByAccountID :many
SELECT * FROM "account_credentials"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3;

-- name: CountAccountCredentialsByAccountID :one
SELECT COUNT("id") FROM "account_credentials"
WHERE "account_id" = $1
LIMIT 1;