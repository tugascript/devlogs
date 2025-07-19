// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
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
	Issuers         []string                           `json:"issuers"`
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

func (ak *AccountCredentialsDTO) UnmarshalJSON(data []byte) error {
	type Alias AccountCredentialsDTO
	aux := &struct {
		ClientSecretJWK json.RawMessage `json:"client_secret_jwk"`
		*Alias
	}{
		Alias: (*Alias)(ak),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.ClientSecretJWK != nil {
		jwk, err := utils.JsonToJWK(aux.ClientSecretJWK)
		if err != nil {
			return err
		}
		ak.ClientSecretJWK = jwk
	}

	return nil
}

func MapAccountCredentialsToDTO(
	accountCredential *database.AccountCredential,
) AccountCredentialsDTO {
	return AccountCredentialsDTO{
		id:          accountCredential.ID,
		ClientID:    accountCredential.ClientID,
		Alias:       accountCredential.Alias,
		Scopes:      accountCredential.Scopes,
		Issuers:     accountCredential.Issuers,
		AuthMethods: accountCredential.AuthMethods,
		accountId:   accountCredential.AccountID,
	}
}

func MapAccountCredentialsToDTOWithJWK(
	accountKeys *database.AccountCredential,
	jwk utils.JWK,
	exp time.Time,
) AccountCredentialsDTO {
	return AccountCredentialsDTO{
		id:              accountKeys.ID,
		Alias:           accountKeys.Alias,
		ClientID:        accountKeys.ClientID,
		ClientSecretID:  jwk.GetKeyID(),
		ClientSecretJWK: jwk,
		ClientSecretExp: exp.Unix(),
		Scopes:          accountKeys.Scopes,
		Issuers:         accountKeys.Issuers,
		AuthMethods:     accountKeys.AuthMethods,
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
		Alias:           accountKeys.Alias,
		ClientID:        accountKeys.ClientID,
		ClientSecretID:  secretID,
		ClientSecret:    fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp: exp.Unix(),
		Scopes:          accountKeys.Scopes,
		Issuers:         accountKeys.Issuers,
		AuthMethods:     accountKeys.AuthMethods,
		accountId:       accountKeys.AccountID,
	}
}
