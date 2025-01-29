// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: accounts.sql

package database

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const confirmAccount = `-- name: ConfirmAccount :one
UPDATE "accounts" SET
    "is_confirmed" = true,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $1
RETURNING id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at
`

func (q *Queries) ConfirmAccount(ctx context.Context, id int32) (Account, error) {
	row := q.db.QueryRow(ctx, confirmAccount, id)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const createAccountWithPassword = `-- name: CreateAccountWithPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "email", 
    "password"
) VALUES (
    $1, 
    $2, 
    $3, 
    $4
) RETURNING id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at
`

type CreateAccountWithPasswordParams struct {
	FirstName string
	LastName  string
	Email     string
	Password  pgtype.Text
}

func (q *Queries) CreateAccountWithPassword(ctx context.Context, arg CreateAccountWithPasswordParams) (Account, error) {
	row := q.db.QueryRow(ctx, createAccountWithPassword,
		arg.FirstName,
		arg.LastName,
		arg.Email,
		arg.Password,
	)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const createAccountWithoutPassword = `-- name: CreateAccountWithoutPassword :one
INSERT INTO "accounts" (
    "first_name",
    "last_name",
    "email",
    "is_confirmed"
) VALUES (
    $1, 
    $2, 
    $3,
    true
) RETURNING id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at
`

type CreateAccountWithoutPasswordParams struct {
	FirstName string
	LastName  string
	Email     string
}

func (q *Queries) CreateAccountWithoutPassword(ctx context.Context, arg CreateAccountWithoutPasswordParams) (Account, error) {
	row := q.db.QueryRow(ctx, createAccountWithoutPassword, arg.FirstName, arg.LastName, arg.Email)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findAccountByEmail = `-- name: FindAccountByEmail :one
SELECT id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at FROM "accounts"
WHERE "email" = $1 LIMIT 1
`

func (q *Queries) FindAccountByEmail(ctx context.Context, email string) (Account, error) {
	row := q.db.QueryRow(ctx, findAccountByEmail, email)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findAccountById = `-- name: FindAccountById :one
SELECT id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at FROM "accounts"
WHERE "id" = $1 LIMIT 1
`

func (q *Queries) FindAccountById(ctx context.Context, id int32) (Account, error) {
	row := q.db.QueryRow(ctx, findAccountById, id)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateAccountEmail = `-- name: UpdateAccountEmail :one
UPDATE "accounts" SET
    "email" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at
`

type UpdateAccountEmailParams struct {
	Email string
	ID    int32
}

func (q *Queries) UpdateAccountEmail(ctx context.Context, arg UpdateAccountEmailParams) (Account, error) {
	row := q.db.QueryRow(ctx, updateAccountEmail, arg.Email, arg.ID)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateAccountPassword = `-- name: UpdateAccountPassword :one
UPDATE "accounts" SET
    "password" = $1,
    "version" = "version" + 1,
    "updated_at" = now()
WHERE "id" = $2
RETURNING id, first_name, last_name, email, password, version, is_confirmed, two_factor_type, created_at, updated_at
`

type UpdateAccountPasswordParams struct {
	Password pgtype.Text
	ID       int32
}

func (q *Queries) UpdateAccountPassword(ctx context.Context, arg UpdateAccountPasswordParams) (Account, error) {
	row := q.db.QueryRow(ctx, updateAccountPassword, arg.Password, arg.ID)
	var i Account
	err := row.Scan(
		&i.ID,
		&i.FirstName,
		&i.LastName,
		&i.Email,
		&i.Password,
		&i.Version,
		&i.IsConfirmed,
		&i.TwoFactorType,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
