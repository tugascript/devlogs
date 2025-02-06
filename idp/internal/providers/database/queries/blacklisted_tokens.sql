-- name: BlacklistToken :exec
INSERT INTO "blacklisted_tokens" (
  "id",
  "expires_at"
) VALUES (
  $1,
    $2
);

-- name: GetBlacklistedToken :one
SELECT * FROM "blacklisted_tokens"
WHERE "id" = $1 LIMIT 1;