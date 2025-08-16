// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type AccountCredentialsRegistrationDomainDTO struct {
	id int32

	Domain   string `json:"domain"`
	Verified bool   `json:"verified"`

	VerificationHost          string `json:"verification_host,omitempty"`
	VerificationPrefix        string `json:"verification_prefix,omitempty"`
	VerificationCode          string `json:"verification_code,omitempty"`
	VerificationValue         string `json:"verification_value,omitempty"`
	VerificationCodeExpiresAt int64  `json:"verification_code_expires_at,omitempty"`
}

func (a *AccountCredentialsRegistrationDomainDTO) ID() int32 {
	return a.id
}

func MapAccountCredentialsRegistrationDomainToDTOWithCode(
	domain *database.AccountDynamicRegistrationDomain,
	verificationHost string,
	verificationPrefix string,
	verificationCode string,
	expiresAt time.Time,
) AccountCredentialsRegistrationDomainDTO {
	return AccountCredentialsRegistrationDomainDTO{
		id:                        domain.ID,
		Domain:                    domain.Domain,
		VerificationHost:          verificationHost,
		VerificationPrefix:        verificationPrefix,
		VerificationCode:          verificationCode,
		VerificationValue:         fmt.Sprintf("%s=%s", verificationPrefix, verificationCode),
		VerificationCodeExpiresAt: expiresAt.Unix(),
		Verified:                  false,
	}
}
