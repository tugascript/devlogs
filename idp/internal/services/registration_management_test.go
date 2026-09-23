package services

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

func TestRegistrationTokenState(t *testing.T) {
	id, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	stored := pgtype.UUID{Bytes: id, Valid: true}
	for _, tc := range []struct {
		name          string
		stored        pgtype.UUID
		presented     string
		expiry, valid bool
	}{
		{"current", stored, id.String(), false, true},
		{"wrong identifier", stored, uuid.NewString(), false, false},
		{"missing identifier", stored, "", false, false},
		{"legacy allowed before upgrade", pgtype.UUID{}, "legacy-base62-id", true, true},
		{"legacy needs expiry", pgtype.UUID{}, "legacy-base62-id", false, false},
		{"legacy denied after upgrade", stored, "legacy-base62-id", true, false},
		{"v4 is not v7", pgtype.UUID{Bytes: uuid.Nil, Valid: true}, uuid.Nil.String(), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRegistrationID(tc.stored, tc.presented, tc.expiry)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, error=%v", tc.valid, err)
			}
		})
	}
}

// Embedding pgx.Tx leaves unused methods unavailable: any unexpected query in
// these transaction-boundary tests fails immediately.
type registrationTestTx struct {
	pgx.Tx
	committed, rolledBack bool
	commitErr             error
}

func (tx *registrationTestTx) Begin(context.Context) (pgx.Tx, error) { return tx, nil }
func (tx *registrationTestTx) Commit(context.Context) error          { tx.committed = true; return tx.commitErr }
func (tx *registrationTestTx) Rollback(context.Context) error        { tx.rolledBack = true; return nil }

func TestRegistrationTransactionDoesNotReturnSuccessBeforeCommit(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		operationErr, commitErr bool
	}{
		{"success", false, false}, {"operation rollback", true, false}, {"commit failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &registrationTestTx{}
			if tc.commitErr {
				tx.commitErr = errors.New("commit failed")
			}
			db := &database.Database{}
			s := &Services{
				database: db.InTransaction(tx),
				logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
			}
			if db.Queries != nil {
				t.Fatal("transaction setup mutated shared database")
			}
			var result string
			var err *exceptions.ServiceError
			var panicValue any
			returned := false
			func() {
				defer func() { panicValue = recover() }()
				result, err = registrationTransaction(s, context.Background(), "test-request", func(qrs *database.Queries) (string, *exceptions.ServiceError) {
					if qrs == s.database.Queries {
						t.Fatal("callback received shared queries")
					}
					if tc.operationErr {
						return "uncommitted", exceptions.NewValidationError("invalid metadata")
					}
					return "committed", nil
				})
				returned = true
			}()
			if tc.commitErr {
				if panicValue != tx.commitErr || returned {
					t.Fatalf("expected commit failure panic, got %v (returned=%v)", panicValue, returned)
				}
			} else if panicValue != nil || !returned {
				t.Fatalf("unexpected panic: %v", panicValue)
			} else if tc.operationErr {
				if err == nil || result != "" {
					t.Fatal("returned an uncommitted response")
				}
			} else if err != nil || result != "committed" {
				t.Fatalf("result=%q error=%v", result, err)
			}
			if tx.committed == tc.operationErr {
				t.Fatal("incorrect commit behavior")
			}
			if tx.rolledBack != tc.operationErr {
				t.Fatal("incorrect rollback behavior")
			}
		})
	}
}
