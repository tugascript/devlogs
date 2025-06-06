// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import "github.com/tugascript/devlogs/idp/internal/providers/database"

type AccountDTO struct {
	ID            int32  `json:"id"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Email         string `json:"email"`
	TwoFactorType string `json:"two_factor_type"`

	version       int32
	emailVerified bool
	password      string
	dek           string
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
		ID:            account.ID,
		version:       account.Version,
		GivenName:     account.GivenName,
		FamilyName:    account.FamilyName,
		Email:         account.Email,
		TwoFactorType: account.TwoFactorType,
		emailVerified: account.EmailVerified,
		password:      account.Password.String,
		dek:           account.Dek,
	}
}
