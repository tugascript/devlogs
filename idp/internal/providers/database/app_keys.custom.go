// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package database

import (
	"context"
	"errors"
	"strconv"
)

type FindAppKeysByNamesAndAppIDParams struct {
	AppID int32
	Names []string
}

func buildFindAppKeysByNamesAndAppIDQuery(arg FindAppKeysByNamesAndAppIDParams) (string, error) {
	paramsCount := len(arg.Names)
	if paramsCount == 0 {
		return "", errors.New("names cannot be empty")
	}
	if paramsCount == 1 {
		return `SELECT id, app_id, account_id, name, jwt_crypto_suite, public_kid, public_key, private_key, is_distributed, created_at, updated_at FROM "app_keys" WHERE "id" = $1 AND "name" = $2 LIMIT $3`, nil
	}

	query := `SELECT id, app_id, account_id, name, jwt_crypto_suite, public_kid, public_key, private_key, is_distributed, created_at, updated_at FROM app_keys WHERE "id" = $1 AND "name" IN (`
	for i := 1; i <= paramsCount; i++ {
		query += `$` + strconv.Itoa(i+1)
		if i < paramsCount {
			query += ", "
		}
	}
	query += `) ORDER BY "id" DESC LIMIT ` + strconv.Itoa(paramsCount)

	return query, nil
}

func buildFindAppKeysByNamesAndAppIDArgs(arg FindAppKeysByNamesAndAppIDParams) []interface{} {
	args := make([]interface{}, 0, len(arg.Names)+1)
	args = append(args, arg.AppID)
	for _, name := range arg.Names {
		args = append(args, name)
	}
	return args
}

func (q *Queries) FindAppKeysByNamesAndAppID(ctx context.Context, arg FindAppKeysByNamesAndAppIDParams) ([]AppKey, error) {
	query, err := buildFindAppKeysByNamesAndAppIDQuery(arg)
	if err != nil {
		return nil, err
	}

	rows, err := q.db.Query(ctx, query, buildFindAppKeysByNamesAndAppIDArgs(arg)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AppKey, 0)
	for rows.Next() {
		var i AppKey
		if err := rows.Scan(
			&i.ID,
			&i.AppID,
			&i.AccountID,
			&i.Name,
			&i.JwtCryptoSuite,
			&i.PublicKid,
			&i.PublicKey,
			&i.PrivateKey,
			&i.IsDistributed,
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
