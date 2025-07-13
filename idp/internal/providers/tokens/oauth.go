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

type AccountOAuthTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) CreateOAuthToken(opts AccountOAuthTokenOptions) *jwt.Token {
	return t.createPurposeToken(accountPurposeTokenOptions{
		ttlSec:          t.oauthTTL,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.OAuthBase + paths.OAuthToken,
		purpose:         TokenPurposeOAuth,
	})
}

func (t *Tokens) GetOAuthTTL() int64 {
	return t.oauthTTL
}
