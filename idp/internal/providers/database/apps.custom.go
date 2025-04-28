package database

import (
	"context"
	"errors"
	"strconv"
)

type CountAppsByUsernameColumnsParams struct {
	AccountID       int32
	UsernameColumns []string
}

func buildCountAppsByUsernameColumnsQuery(arg CountAppsByUsernameColumnsParams) (string, error) {
	paramsCount := len(arg.UsernameColumns)
	if paramsCount == 0 {
		return "", errors.New("username columns cannot be empty")
	}
	if paramsCount == 1 {
		return `SELECT COUNT("id") FROM apps WHERE account_id = $1 AND username_column = $2 LIMIT 1`, nil
	}

	query := `SELECT COUNT("id") FROM apps WHERE account_id = $1 AND username_column IN (`
	for i := 1; i <= paramsCount; i++ {
		query += `$` + strconv.Itoa(i+1)
		if i < paramsCount {
			query += ", "
		}
	}
	query += `) LIMIT 1`
	return query, nil
}

func buildCountAppsByUsernameArgs(arg CountAppsByUsernameColumnsParams) []interface{} {
	args := make([]interface{}, 0, len(arg.UsernameColumns)+1)
	args = append(args, arg.AccountID)
	for _, usernameColumn := range arg.UsernameColumns {
		args = append(args, usernameColumn)
	}
	return args
}

func (q *Queries) CountAppsByUsernameColumns(ctx context.Context, arg CountAppsByUsernameColumnsParams) (int32, error) {
	query, err := buildCountAppsByUsernameColumnsQuery(arg)
	if err != nil {
		return 0, err
	}

	row := q.db.QueryRow(ctx, query, buildCountAppsByUsernameArgs(arg)...)
	var count int32
	err = row.Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
