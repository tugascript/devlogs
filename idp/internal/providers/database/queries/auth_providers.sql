-- name: CreateAuthProvider :exec
INSERT INTO "auth_providers" (
  "email",
  "provider"
) VALUES (
  $1,
  $2
);

-- name: FindAuthProviderByEmailAndProvider :one
SELECT * FROM "auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" = $2
LIMIT 1;

-- name: DeleteExternalAuthProviders :exec
DELETE FROM "auth_providers"
WHERE 
  "email" = $1 AND 
  "provider" != $2;
