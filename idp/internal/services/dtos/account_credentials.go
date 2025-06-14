// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AccountCredentialsDTO struct {
	ClientID        string                             `json:"client_id"`
	Alias           string                             `json:"alias"`
	Scopes          []database.AccountCredentialsScope `json:"scopes"`
	AuthMethods     []database.AuthMethod              `json:"auth_methods"`
	ClientSecretID  string                             `json:"client_secret_id,omitempty"`
	ClientSecret    string                             `json:"client_secret,omitempty"`
	ClientSecretJWK utils.JWK                          `json:"client_secret_jwk,omitempty"`
	ClientSecretExp int64                              `json:"client_secret_exp,omitempty"`

	id        int32
	accountId int32
}

func (ak *AccountCredentialsDTO) AccountID() int32 {
	return ak.accountId
}

func (ak *AccountCredentialsDTO) ID() int32 {
	return ak.id
}

func MapAccountCredentialsToDTO(
	accountKeys *database.AccountCredential,
) AccountCredentialsDTO {
	return AccountCredentialsDTO{
		id:          accountKeys.ID,
		ClientID:    accountKeys.ClientID,
		Scopes:      accountKeys.Scopes,
		AuthMethods: accountKeys.AuthMethods,
		accountId:   accountKeys.AccountID,
	}
}

func MapAccountCredentialsToDTOWithJWK(
	accountKeys *database.AccountCredential,
	jwk utils.JWK,
	exp time.Time,
) AccountCredentialsDTO {
	return AccountCredentialsDTO{
		id:              accountKeys.ID,
		ClientID:        accountKeys.ClientID,
		ClientSecretID:  jwk.GetKeyID(),
		ClientSecretJWK: jwk,
		ClientSecretExp: exp.Unix(),
		accountId:       accountKeys.AccountID,
	}
}

func MapAccountCredentialsToDTOWithSecret(
	accountKeys *database.AccountCredential,
	secretID,
	secret string,
	exp time.Time,
) AccountCredentialsDTO {
	return AccountCredentialsDTO{
		id:              accountKeys.ID,
		ClientID:        accountKeys.ClientID,
		ClientSecretID:  secretID,
		ClientSecret:    fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp: exp.Unix(),
		accountId:       accountKeys.AccountID,
	}
}
