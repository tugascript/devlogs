// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AccountDTO struct {
	PublicID      uuid.UUID              `json:"id"`
	GivenName     string                 `json:"given_name"`
	FamilyName    string                 `json:"family_name"`
	Email         string                 `json:"email"`
	Username      string                 `json:"username"`
	TwoFactorType database.TwoFactorType `json:"two_factor_type"`

	id            int32
	version       int32
	emailVerified bool
	password      string
	dek           string
}

func (a *AccountDTO) ID() int32 {
	return a.id
}

func (a *AccountDTO) Version() int32 {
	return a.version
}

func (a *AccountDTO) Password() string {
	return a.password
}

func (a *AccountDTO) EmailVerified() bool {
	return a.emailVerified
}

func (a *AccountDTO) DEK() string {
	return a.dek
}

func MapAccountToDTO(account *database.Account) AccountDTO {
	return AccountDTO{
		id:            account.ID,
		PublicID:      account.PublicID,
		version:       account.Version,
		GivenName:     account.GivenName,
		FamilyName:    account.FamilyName,
		Email:         account.Email,
		TwoFactorType: account.TwoFactorType,
		Username:      account.Username,
		emailVerified: account.EmailVerified,
		password:      account.Password.String,
		dek:           account.Dek,
	}
}
