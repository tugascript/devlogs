// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type UserDTO struct {
	ID            int32  `json:"id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	TwoFactorType string `json:"two_factor_type"`
	DataDTO

	version       int32
	emailVerified bool
	password      string
	dek           string
}

func (u *UserDTO) Version() int32 {
	return u.version
}

func (u *UserDTO) Password() string {
	return u.password
}

func (u *UserDTO) EmailVerified() bool {
	return u.emailVerified
}

func (u *UserDTO) DEK() string {
	return u.dek
}

func MapUserToDTO(user *database.User) (UserDTO, *exceptions.ServiceError) {
	data := make(DataDTO)
	if err := json.Unmarshal(user.UserData, &data); err != nil {
		return UserDTO{}, exceptions.NewServerError()
	}

	return UserDTO{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Username,
		TwoFactorType: user.TwoFactorType,
		DataDTO:       data,
		version:       user.Version,
		emailVerified: user.EmailVerified,
		password:      user.Password.String,
		dek:           user.Dek,
	}, nil
}
