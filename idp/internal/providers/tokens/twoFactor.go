// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

type Account2FATokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) Create2FAToken(opts Account2FATokenOptions) *jwt.Token {
	return t.createPurposeToken(accountPurposeTokenOptions{
		ttlSec:          t.twoFATTL,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.AuthLogin + paths.Auth2FA,
		purpose:         TokenPurpose2FA,
	})
}

func (t *Tokens) Get2FATTL() int64 {
	return t.twoFATTL
}
