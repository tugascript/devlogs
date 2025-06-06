// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AppProfileDTO struct {
	ID    int32    `json:"id"`
	Roles []string `json:"roles"`
}

func MapAppProfileToDTO(appProfile *database.AppProfile) (AppProfileDTO, *exceptions.ServiceError) {
	roles, serviceErr := jsonHashMapToSlice(appProfile.UserRoles)
	if serviceErr != nil {
		return AppProfileDTO{}, serviceErr
	}

	return AppProfileDTO{
		ID:    appProfile.ID,
		Roles: roles,
	}, nil
}
