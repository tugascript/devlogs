// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"time"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AuthProviderDTO struct {
	Provider     string `json:"provider"`
	RegisteredAt string `json:"registered_at"`

	id int32
}

func (a *AuthProviderDTO) ID() int32 {
	return a.id
}

func MapAccountAuthProviderToDTO(provider *database.AccountAuthProvider) AuthProviderDTO {
	return AuthProviderDTO{
		id:           provider.ID,
		Provider:     string(provider.Provider),
		RegisteredAt: provider.CreatedAt.Format(time.RFC3339),
	}
}
