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
	ID            int    `json:"id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	TwoFactorType string `json:"two_factor_type"`
	DataDTO

	version     int
	isConfirmed bool
	password    string
}

func (u *UserDTO) Version() int {
	return u.version
}

func (u *UserDTO) Password() string {
	return u.password
}

func (u *UserDTO) IsConfirmed() bool {
	return u.isConfirmed
}

func MapUserToDTO(user *database.User) (UserDTO, *exceptions.ServiceError) {
	data := make(DataDTO)
	if err := json.Unmarshal(user.UserData, &data); err != nil {
		return UserDTO{}, exceptions.NewServerError()
	}

	return UserDTO{
		ID:            int(user.ID),
		Email:         user.Email,
		Username:      user.Username,
		TwoFactorType: user.TwoFactorType,
		DataDTO:       data,
		version:       int(user.Version),
		isConfirmed:   user.IsConfirmed,
		password:      user.Password.String,
	}, nil
}
