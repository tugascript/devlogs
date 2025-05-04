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

type AppProfileDTO struct {
	id          int
	appID       int
	userID      int
	accountID   int
	userRoles   []string
	profileData map[string]any
}

func (ap *AppProfileDTO) ID() int {
	return ap.id
}

func (ap *AppProfileDTO) AppID() int {
	return ap.appID
}

func (ap *AppProfileDTO) UserID() int {
	return ap.userID
}

func (ap *AppProfileDTO) AccountID() int {
	return ap.accountID
}

func (ap *AppProfileDTO) UserRoles() []string {
	return ap.userRoles
}

func (ap *AppProfileDTO) ProfileData() map[string]any {
	return ap.profileData
}

func MapAppProfileToDTO(appProfile *database.AppProfile) (AppProfileDTO, *exceptions.ServiceError) {
	userRoles, serviceErr := hashMapToSlice(appProfile.UserRoles)
	if serviceErr != nil {
		return AppProfileDTO{}, serviceErr
	}

	profileData := make(map[string]any)
	if err := json.Unmarshal(appProfile.ProfileData, &profileData); err != nil {
		return AppProfileDTO{}, exceptions.NewServerError()
	}

	return AppProfileDTO{
		id:          int(appProfile.ID),
		appID:       int(appProfile.AppID),
		userID:      int(appProfile.UserID),
		accountID:   int(appProfile.AccountID),
		userRoles:   userRoles,
		profileData: profileData,
	}, nil
}
