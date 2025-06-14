// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tokens

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

type Account2FATokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) Create2FAToken(opts Account2FATokenOptions) (string, error) {
	return t.createPurposeToken(accountPurposeTokenOptions{
		privateKey:      t.twoFAData.curKeyPair.privateKey,
		kid:             t.twoFAData.curKeyPair.kid,
		ttlSec:          t.twoFAData.ttlSec,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.AuthLogin + paths.TwoFA,
		purpose:         TokenPurpose2FA,
	})
}

func (t *Tokens) Verify2FAToken(token string) (AccountClaims, error) {
	claims, err := verifyPurposeToken(token, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.twoFAData.prevPubKey != nil && t.twoFAData.prevPubKey.kid == kid {
			return t.twoFAData.prevPubKey.publicKey, nil
		}
		if t.twoFAData.curKeyPair.kid == kid {
			return t.twoFAData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, err
	}

	return claims.AccountClaims, nil
}

func (t *Tokens) Get2FATTL() int64 {
	return t.twoFAData.ttlSec
}
