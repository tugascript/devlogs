// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"

	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type UserDTO struct {
	PublicID      uuid.UUID              `json:"id"`
	Email         string                 `json:"email"`
	Username      string                 `json:"username"`
	UserRoles     []string               `json:"user_roles"`
	TwoFactorType database.TwoFactorType `json:"two_factor_type"`
	DataDTO

	id            int32
	version       int32
	emailVerified bool
	password      string
}

func (u *UserDTO) ID() int32 {
	return u.id
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

func MapUserToDTO(user *database.User) (UserDTO, *exceptions.ServiceError) {
	data := make(DataDTO)
	if err := json.Unmarshal(user.UserData, &data); err != nil {
		return UserDTO{}, exceptions.NewInternalServerError()
	}

	return UserDTO{
		id:            user.ID,
		PublicID:      user.PublicID,
		Email:         user.Email,
		Username:      user.Username,
		UserRoles:     user.UserRoles,
		TwoFactorType: user.TwoFactorType,
		DataDTO:       data,
		version:       user.Version,
		emailVerified: user.EmailVerified,
		password:      user.Password.String,
	}, nil
}
