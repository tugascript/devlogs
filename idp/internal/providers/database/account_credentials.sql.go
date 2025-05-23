// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: account_credentials.sql

package database

import (
	"context"
)

const countAccountCredentialsByAccountID = `-- name: CountAccountCredentialsByAccountID :one
SELECT COUNT("id") FROM "account_credentials"
WHERE "account_id" = $1
LIMIT 1
`

func (q *Queries) CountAccountCredentialsByAccountID(ctx context.Context, accountID int32) (int64, error) {
	row := q.db.QueryRow(ctx, countAccountCredentialsByAccountID, accountID)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const countAccountCredentialsByAliasAndAccountID = `-- name: CountAccountCredentialsByAliasAndAccountID :one
SELECT COUNT("id") FROM "account_credentials"
WHERE "account_id" = $1 AND "alias" = $2
`

type CountAccountCredentialsByAliasAndAccountIDParams struct {
	AccountID int32
	Alias     string
}

func (q *Queries) CountAccountCredentialsByAliasAndAccountID(ctx context.Context, arg CountAccountCredentialsByAliasAndAccountIDParams) (int64, error) {
	row := q.db.QueryRow(ctx, countAccountCredentialsByAliasAndAccountID, arg.AccountID, arg.Alias)
	var count int64
	err := row.Scan(&count)
	return count, err
}

const createAccountCredentials = `-- name: CreateAccountCredentials :one
INSERT INTO "account_credentials" (
    "client_id",
    "client_secret",
    "account_id",
    "alias",
    "scopes"
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5
) RETURNING id, account_id, scopes, alias, client_id, client_secret, created_at, updated_at
`

type CreateAccountCredentialsParams struct {
	ClientID     string
	ClientSecret string
	AccountID    int32
	Alias        string
	Scopes       []byte
}

func (q *Queries) CreateAccountCredentials(ctx context.Context, arg CreateAccountCredentialsParams) (AccountCredential, error) {
	row := q.db.QueryRow(ctx, createAccountCredentials,
		arg.ClientID,
		arg.ClientSecret,
		arg.AccountID,
		arg.Alias,
		arg.Scopes,
	)
	var i AccountCredential
	err := row.Scan(
		&i.ID,
		&i.AccountID,
		&i.Scopes,
		&i.Alias,
		&i.ClientID,
		&i.ClientSecret,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const deleteAccountCredentials = `-- name: DeleteAccountCredentials :exec
DELETE FROM "account_credentials"
WHERE "client_id" = $1
`

func (q *Queries) DeleteAccountCredentials(ctx context.Context, clientID string) error {
	_, err := q.db.Exec(ctx, deleteAccountCredentials, clientID)
	return err
}

const findAccountCredentialsByClientID = `-- name: FindAccountCredentialsByClientID :one

SELECT id, account_id, scopes, alias, client_id, client_secret, created_at, updated_at FROM "account_credentials"
WHERE "client_id" = $1
LIMIT 1
`

// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
func (q *Queries) FindAccountCredentialsByClientID(ctx context.Context, clientID string) (AccountCredential, error) {
	row := q.db.QueryRow(ctx, findAccountCredentialsByClientID, clientID)
	var i AccountCredential
	err := row.Scan(
		&i.ID,
		&i.AccountID,
		&i.Scopes,
		&i.Alias,
		&i.ClientID,
		&i.ClientSecret,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const findPaginatedAccountCredentialsByAccountID = `-- name: FindPaginatedAccountCredentialsByAccountID :many
SELECT id, account_id, scopes, alias, client_id, client_secret, created_at, updated_at FROM "account_credentials"
WHERE "account_id" = $1
ORDER BY "id" DESC
OFFSET $2 LIMIT $3
`

type FindPaginatedAccountCredentialsByAccountIDParams struct {
	AccountID int32
	Offset    int32
	Limit     int32
}

func (q *Queries) FindPaginatedAccountCredentialsByAccountID(ctx context.Context, arg FindPaginatedAccountCredentialsByAccountIDParams) ([]AccountCredential, error) {
	rows, err := q.db.Query(ctx, findPaginatedAccountCredentialsByAccountID, arg.AccountID, arg.Offset, arg.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []AccountCredential{}
	for rows.Next() {
		var i AccountCredential
		if err := rows.Scan(
			&i.ID,
			&i.AccountID,
			&i.Scopes,
			&i.Alias,
			&i.ClientID,
			&i.ClientSecret,
			&i.CreatedAt,
			&i.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const updateAccountCredentials = `-- name: UpdateAccountCredentials :one
UPDATE "account_credentials" SET
    "scopes" = $1,
    "alias" = $2,
    "updated_at" = now()
WHERE "id" = $3
RETURNING id, account_id, scopes, alias, client_id, client_secret, created_at, updated_at
`

type UpdateAccountCredentialsParams struct {
	Scopes []byte
	Alias  string
	ID     int32
}

func (q *Queries) UpdateAccountCredentials(ctx context.Context, arg UpdateAccountCredentialsParams) (AccountCredential, error) {
	row := q.db.QueryRow(ctx, updateAccountCredentials, arg.Scopes, arg.Alias, arg.ID)
	var i AccountCredential
	err := row.Scan(
		&i.ID,
		&i.AccountID,
		&i.Scopes,
		&i.Alias,
		&i.ClientID,
		&i.ClientSecret,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}

const updateAccountCredentialsClientSecret = `-- name: UpdateAccountCredentialsClientSecret :one
UPDATE "account_credentials" SET
    "client_secret" = $1,
    "updated_at" = now()
WHERE "client_id" = $2
RETURNING id, account_id, scopes, alias, client_id, client_secret, created_at, updated_at
`

type UpdateAccountCredentialsClientSecretParams struct {
	ClientSecret string
	ClientID     string
}

func (q *Queries) UpdateAccountCredentialsClientSecret(ctx context.Context, arg UpdateAccountCredentialsClientSecretParams) (AccountCredential, error) {
	row := q.db.QueryRow(ctx, updateAccountCredentialsClientSecret, arg.ClientSecret, arg.ClientID)
	var i AccountCredential
	err := row.Scan(
		&i.ID,
		&i.AccountID,
		&i.Scopes,
		&i.Alias,
		&i.ClientID,
		&i.ClientSecret,
		&i.CreatedAt,
		&i.UpdatedAt,
	)
	return i, err
}
