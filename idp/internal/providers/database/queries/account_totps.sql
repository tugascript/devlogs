-- name: CreateAccountTotps :exec
INSERT INTO "account_totps" (
  "account_id",
  "url",
  "secret",
  "dek",
  "recovery_codes"
) VALUES (
  $1,
  $2,
  $3,
  $4,
  $5
);

-- name: FindAccountTotpByAccountID :one
SELECT * FROM "account_totps"
WHERE "account_id" = $1 LIMIT 1;

-- name: UpdateAccountTotpByAccountID :exec
UPDATE "account_totps" SET
    "dek" = $1
WHERE "account_id" = $2;

-- name: DeleteAccountRecoveryKeys :exec
DELETE FROM "account_totps"
WHERE "account_id" = $1;