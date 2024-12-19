package database

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/joho/godotenv/autoload"
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

func (database *Database) BeginTx(ctx context.Context) (*Queries, pgx.Tx, error) {
	txn, err := database.connPool.BeginTx(ctx, pgx.TxOptions{
		DeferrableMode: pgx.Deferrable,
		IsoLevel:       pgx.ReadCommitted,
		AccessMode:     pgx.ReadWrite,
	})

	if err != nil {
		return nil, nil, err
	}

	return database.WithTx(txn), txn, nil
}

func (database *Database) FinalizeTx(ctx context.Context, txn pgx.Tx, err error) {
	if p := recover(); p != nil {
		if err := txn.Rollback(ctx); err != nil {
			panic(err)
		}
		panic(p)
	}
	if err != nil {
		if err := txn.Rollback(ctx); err != nil {
			panic(err)
		}
		return
	}
	if commitErr := txn.Commit(ctx); commitErr != nil {
		panic(commitErr)
	}
}

func (database *Database) RawQuery(ctx context.Context, sql string, args []interface{}) (pgx.Rows, error) {
	return database.connPool.Query(ctx, sql, args...)
}

func (database *Database) RawQueryRow(ctx context.Context, sql string, args []interface{}) pgx.Row {
	return database.connPool.QueryRow(ctx, sql, args...)
}
