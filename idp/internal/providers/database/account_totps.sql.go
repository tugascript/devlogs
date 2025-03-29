// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: account_totps.sql

package database

import (
	"context"
)

const createAccountTotps = `-- name: CreateAccountTotps :exec
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
)
`

type CreateAccountTotpsParams struct {
	AccountID     int32
	Url           string
	Secret        string
	Dek           string
	RecoveryCodes []byte
}

func (q *Queries) CreateAccountTotps(ctx context.Context, arg CreateAccountTotpsParams) error {
	_, err := q.db.Exec(ctx, createAccountTotps,
		arg.AccountID,
		arg.Url,
		arg.Secret,
		arg.Dek,
		arg.RecoveryCodes,
	)
	return err
}

const deleteAccountRecoveryKeys = `-- name: DeleteAccountRecoveryKeys :exec
DELETE FROM "account_totps"
WHERE "account_id" = $1
`

func (q *Queries) DeleteAccountRecoveryKeys(ctx context.Context, accountID int32) error {
	_, err := q.db.Exec(ctx, deleteAccountRecoveryKeys, accountID)
	return err
}

const findAccountTotpByAccountID = `-- name: FindAccountTotpByAccountID :one
SELECT id, account_id, url, secret, dek, recovery_codes, created_at, updated_at FROM "account_totps"
WHERE "account_id" = $1 LIMIT 1
`

func (q *Queries) FindAccountTotpByAccountID(ctx context.Context, accountID int32) (AccountTotp, error) {
	row := q.db.QueryRow(ctx, findAccountTotpByAccountID, accountID)
	var i AccountTotp
	err := row.Scan(
		&i.ID,
		&i.AccountID,
		&i.Url,
		&i.Secret,
		&i.Dek,
		&i.RecoveryCodes,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateAccountTotpByAccountID = `-- name: UpdateAccountTotpByAccountID :exec
UPDATE "account_totps" SET
    "dek" = $1
WHERE "account_id" = $2
`

type UpdateAccountTotpByAccountIDParams struct {
	Dek       string
	AccountID int32
}

func (q *Queries) UpdateAccountTotpByAccountID(ctx context.Context, arg UpdateAccountTotpByAccountIDParams) error {
	_, err := q.db.Exec(ctx, updateAccountTotpByAccountID, arg.Dek, arg.AccountID)
	return err
}
