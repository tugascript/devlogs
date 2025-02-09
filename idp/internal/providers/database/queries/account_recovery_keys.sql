-- name: CreateAccountRecoveryKeys :exec
INSERT INTO "account_recovery_keys" (
  "account_id",
  "keys"
) VALUES (
  $1,
  $2
);

-- name: DeleteAccountRecoveryKeys :exec
DELETE FROM "account_recovery_keys"
WHERE "account_id" = $1;