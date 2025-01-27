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