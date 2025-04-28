package database

import (
	"context"
	"errors"
)

type RemoveUserUserDataFieldsParams struct {
	AccountID int32
	Fields    []string
}

func buildRemoveUserUserDataFieldsQuery(arg RemoveUserUserDataFieldsParams) (string, error) {
	paramsCount := len(arg.Fields)
	if paramsCount == 0 {
		return "", errors.New("fields cannot be empty")
	}

	return `UPDATE "users" SET "user_data" = "user_data" - $1 WHERE "account_id" = $2`, nil
}

func buildRemoveUserUserDataFieldsArgs(arg RemoveUserUserDataFieldsParams) []interface{} {
	if len(arg.Fields) == 1 {
		return []interface{}{arg.Fields[0], arg.AccountID}
	}
	return []interface{}{arg.Fields, arg.AccountID}
}

func (q *Queries) RemoveUserUserDataFields(ctx context.Context, arg RemoveUserUserDataFieldsParams) error {
	query, err := buildRemoveUserUserDataFieldsQuery(arg)
	if err != nil {
		return err
	}

	_, err = q.db.Exec(ctx, query, buildRemoveUserUserDataFieldsArgs(arg)...)
	return err
}
