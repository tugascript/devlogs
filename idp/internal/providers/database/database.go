// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package database

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

type Database struct {
	connPool *pgxpool.Pool
	*Queries
}

func NewDatabase(connPool *pgxpool.Pool) *Database {
	return &Database{
		connPool: connPool,
		Queries:  New(connPool),
	}
}

func (d *Database) BeginTx(ctx context.Context) (*Queries, pgx.Tx, error) {
	txn, err := d.connPool.BeginTx(ctx, pgx.TxOptions{
		DeferrableMode: pgx.Deferrable,
		IsoLevel:       pgx.ReadCommitted,
		AccessMode:     pgx.ReadWrite,
	})

	if err != nil {
		return nil, nil, err
	}

	return d.WithTx(txn), txn, nil
}

func (d *Database) FinalizeTx(ctx context.Context, txn pgx.Tx, err error, serviceErr *exceptions.ServiceError) {
	if serviceErr != nil || err != nil {
		if err := txn.Rollback(ctx); err != nil {
			panic(err)
		}
		return
	}
	if commitErr := txn.Commit(ctx); commitErr != nil {
		panic(commitErr)
	}
	if p := recover(); p != nil {
		if err := txn.Rollback(ctx); err != nil {
			panic(err)
		}
		panic(p)
	}
}

func (d *Database) RawQuery(ctx context.Context, sql string, args []interface{}) (pgx.Rows, error) {
	return d.connPool.Query(ctx, sql, args...)
}

func (d *Database) RawQueryRow(ctx context.Context, sql string, args []interface{}) pgx.Row {
	return d.connPool.QueryRow(ctx, sql, args...)
}

func (d *Database) Ping(ctx context.Context) error {
	return d.connPool.Ping(ctx)
}
