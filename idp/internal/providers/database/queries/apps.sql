-- name: FindAppIDBySlug :one
SELECT "id" FROM "apps"
WHERE "slug" = $1 LIMIT 1;

-- name: CreateApp :one
INSERT INTO "apps" (
    "id",
    "account_id",
    "name",
    "slug",
    "secret"
) VALUES (
    $1, 
    $2, 
    $3,
    $4,
    $5
) RETURNING *;
