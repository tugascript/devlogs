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

type AccountConfirmationTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) CreateConfirmationToken(opts AccountConfirmationTokenOptions) (string, error) {
	return t.createPurposeToken(accountPurposeTokenOptions{
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.AuthConfirmEmail,
		purpose:         TokenPurposeConfirmation,
		ttlSec:          t.confirmationData.ttlSec,
		privateKey:      t.confirmationData.curKeyPair.privateKey,
		kid:             t.confirmationData.curKeyPair.kid,
	})
}

func (t *Tokens) VerifyConfirmationToken(token string) (AccountClaims, error) {
	claims, err := verifyPurposeToken(token, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.confirmationData.prevPubKey != nil && t.confirmationData.prevPubKey.kid == kid {
			return t.confirmationData.prevPubKey.publicKey, nil
		}
		if t.confirmationData.curKeyPair.kid == kid {
			return t.confirmationData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, err
	}

	return claims.AccountClaims, nil
}
