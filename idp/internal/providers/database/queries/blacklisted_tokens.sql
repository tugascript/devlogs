-- name: BlacklistToken :exec
INSERT INTO "blacklisted_tokens" (
  "id",
  "jwt",
  "expires_at"
) VALUES (
  $1,
    $2,
  $3
);

-- name: GetBlacklistedToken :one
SELECT * FROM "blacklisted_tokens"
WHERE "id" = $1 LIMIT 1;