-- name: DeleteDistributedAppKeysByAppID :exec
DELETE FROM "app_keys"
WHERE "app_id" = $1 AND "is_distributed" = true;
