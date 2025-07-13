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

type AccountConfirmationTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) CreateConfirmationToken(opts AccountConfirmationTokenOptions) *jwt.Token {
	return t.createPurposeToken(accountPurposeTokenOptions{
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.AuthConfirmEmail,
		purpose:         TokenPurposeConfirmation,
		ttlSec:          t.confirmationTTL,
	})
}

func (t *Tokens) GetConfirmationTTL() int64 {
	return t.confirmationTTL
}
