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

type DynamicRegistrationDomainCodeDTO struct {
	id int32

	VerificationHost          string `json:"verification_host"`
	VerificationPrefix        string `json:"verification_prefix"`
	VerificationCode          string `json:"verification_code,omitempty"`
	VerificationValue         string `json:"verification_value,omitempty"`
	VerificationCodeExpiresAt int64  `json:"verification_code_expires_at"`
}

func (a *DynamicRegistrationDomainCodeDTO) ID() int32 {
	return a.id
}

func MapDynamicRegistrationDomainCodeToDTO(
	domainCode *database.DynamicRegistrationDomainCode,
) DynamicRegistrationDomainCodeDTO {
	return DynamicRegistrationDomainCodeDTO{
		id:                        domainCode.ID,
		VerificationHost:          domainCode.VerificationHost,
		VerificationPrefix:        domainCode.VerificationPrefix,
		VerificationCode:          domainCode.VerificationCode,
		VerificationCodeExpiresAt: domainCode.ExpiresAt.Unix(),
	}
}

func CreateDynamicRegistrationDomainCodeDTO(
	verificationHost string,
	verificationPrefix string,
	verificationCode string,
	expiresAt time.Time,
) DynamicRegistrationDomainCodeDTO {
	return DynamicRegistrationDomainCodeDTO{
		VerificationHost:          verificationHost,
		VerificationPrefix:        verificationPrefix,
		VerificationCode:          verificationCode,
		VerificationValue:         fmt.Sprintf("%s=%s", verificationPrefix, verificationCode),
		VerificationCodeExpiresAt: expiresAt.Unix(),
	}
}
