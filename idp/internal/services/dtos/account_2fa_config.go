// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type Account2FATOTPConfigDTO struct {
	AccessToken  string `json:"access_token"`
	Image        string `json:"image"`
	RecoveryKeys string `json:"recovery_keys"`
	ExpiresIn    int64  `json:"expires_in"`
	Message      string `json:"message"`
}

type Account2FACodeConfigDTO struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int64  `json:"expires_in"`
	Message     string `json:"message"`
}

type Account2FAConfigDTO struct {
	id int32

	TwoFactorType database.TwoFactorType `json:"two_factor_type"`
	IsDefault     bool                   `json:"is_default"`
	CreatedAt     int64                  `json:"created_at"`

	// TOTP 2FA
	*Account2FATOTPConfigDTO

	// Email & TOTP Deletion 2FA
	*Account2FACodeConfigDTO
}

func (a *Account2FAConfigDTO) ID() int32 {
	return a.id
}

func MapAccount2FAConfigToDTO(account2FAConfig *database.Account2faConfig) Account2FAConfigDTO {
	return Account2FAConfigDTO{
		id:            account2FAConfig.ID,
		TwoFactorType: account2FAConfig.TwoFactorType,
		IsDefault:     account2FAConfig.IsDefault,
		CreatedAt:     account2FAConfig.CreatedAt.Unix(),
	}
}

func MapAccount2FAConfigTOTPToDTO(
	account2FAConfig *database.Account2faConfig,
	accessToken string,
	image string,
	recoveryKeys string,
	expiresIn int64,
	message string,
) Account2FAConfigDTO {
	return Account2FAConfigDTO{
		id:            account2FAConfig.ID,
		TwoFactorType: account2FAConfig.TwoFactorType,
		IsDefault:     account2FAConfig.IsDefault,
		CreatedAt:     account2FAConfig.CreatedAt.Unix(),
		Account2FATOTPConfigDTO: &Account2FATOTPConfigDTO{
			AccessToken:  accessToken,
			Image:        image,
			RecoveryKeys: recoveryKeys,
			ExpiresIn:    expiresIn,
			Message:      message,
		},
	}
}

func MapAccount2FAConfigCodeToDTO(
	account2FAConfig *database.Account2faConfig,
	accessToken string,
	expiresIn int64,
	message string,
) Account2FAConfigDTO {
	return Account2FAConfigDTO{
		id:            account2FAConfig.ID,
		TwoFactorType: account2FAConfig.TwoFactorType,
		IsDefault:     account2FAConfig.IsDefault,
		CreatedAt:     account2FAConfig.CreatedAt.Unix(),
		Account2FACodeConfigDTO: &Account2FACodeConfigDTO{
			AccessToken: accessToken,
			ExpiresIn:   expiresIn,
			Message:     message,
		},
	}
}
