// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"

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

func (a Account2FAConfigDTO) MarshalJSON() ([]byte, error) {
	type base struct {
		TwoFactorType database.TwoFactorType `json:"two_factor_type"`
		IsDefault     bool                   `json:"is_default"`
		CreatedAt     int64                  `json:"created_at"`
	}
	common := base{
		TwoFactorType: a.TwoFactorType,
		IsDefault:     a.IsDefault,
		CreatedAt:     a.CreatedAt,
	}

	if a.Account2FATOTPConfigDTO != nil {
		return json.Marshal(struct {
			base
			*Account2FATOTPConfigDTO
		}{base: common, Account2FATOTPConfigDTO: a.Account2FATOTPConfigDTO})
	}
	if a.Account2FACodeConfigDTO != nil {
		return json.Marshal(struct {
			base
			*Account2FACodeConfigDTO
		}{base: common, Account2FACodeConfigDTO: a.Account2FACodeConfigDTO})
	}

	return json.Marshal(common)
}

func (a *Account2FAConfigDTO) UnmarshalJSON(data []byte) error {
	var value struct {
		TwoFactorType database.TwoFactorType `json:"two_factor_type"`
		IsDefault     bool                   `json:"is_default"`
		CreatedAt     int64                  `json:"created_at"`
		AccessToken   string                 `json:"access_token"`
		Image         string                 `json:"image"`
		RecoveryKeys  string                 `json:"recovery_keys"`
		ExpiresIn     int64                  `json:"expires_in"`
		Message       string                 `json:"message"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	a.TwoFactorType = value.TwoFactorType
	a.IsDefault = value.IsDefault
	a.CreatedAt = value.CreatedAt
	if value.AccessToken == "" && value.ExpiresIn == 0 && value.Message == "" && value.Image == "" && value.RecoveryKeys == "" {
		return nil
	}

	if value.TwoFactorType == database.TwoFactorTypeTotp {
		a.Account2FATOTPConfigDTO = &Account2FATOTPConfigDTO{
			AccessToken:  value.AccessToken,
			Image:        value.Image,
			RecoveryKeys: value.RecoveryKeys,
			ExpiresIn:    value.ExpiresIn,
			Message:      value.Message,
		}
		return nil
	}

	a.Account2FACodeConfigDTO = &Account2FACodeConfigDTO{
		AccessToken: value.AccessToken,
		ExpiresIn:   value.ExpiresIn,
		Message:     value.Message,
	}
	return nil
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
