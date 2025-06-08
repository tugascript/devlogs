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

type AccountOAuthTokenOptions struct {
	PublicID uuid.UUID
	Version  int32
}

func (t *Tokens) CreateOAuthToken(opts AccountOAuthTokenOptions) (string, error) {
	return t.createPurposeToken(accountPurposeTokenOptions{
		privateKey:      t.oauthData.curKeyPair.privateKey,
		kid:             t.oauthData.curKeyPair.kid,
		ttlSec:          t.oauthData.ttlSec,
		accountPublicID: opts.PublicID,
		accountVersion:  opts.Version,
		path:            paths.AuthBase + paths.OAuthBase + paths.OAuthToken,
		purpose:         TokenPurposeOAuth,
	})
}

func (t *Tokens) VerifyOAuthToken(token string) (AccountClaims, error) {
	claims, err := verifyPurposeToken(token, func(token *jwt.Token) (any, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.oauthData.prevPubKey != nil && t.oauthData.prevPubKey.kid == kid {
			return t.oauthData.prevPubKey.publicKey, nil
		}
		if t.oauthData.curKeyPair.kid == kid {
			return t.oauthData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, err
	}

	return claims.AccountClaims, nil
}

func (t *Tokens) GetOAuthTTL() int64 {
	return t.oauthData.ttlSec
}
