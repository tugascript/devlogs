package tokens

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (t *Tokens) CreateRefreshToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(accountTokenOptions{
		method:         jwt.SigningMethodEdDSA,
		privateKey:     t.refreshData.curKeyPair.privateKey,
		kid:            t.refreshData.curKeyPair.kid,
		ttlSec:         t.refreshData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
		scopes:         []AccountScope{AccountScopeRefresh},
	})
}

func (t *Tokens) VerifyRefreshToken(token string) (AccountClaims, []AccountScope, uuid.UUID, time.Time, error) {
	claims, err := verifyToken(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractUserTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.refreshData.prevPubKey != nil && t.refreshData.prevPubKey.kid == kid {
			return t.refreshData.prevPubKey.publicKey, nil
		}
		if t.refreshData.curKeyPair.kid == kid {
			return t.refreshData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	scopes, err := splitAccountScopes(claims.Scopes)
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return AccountClaims{}, nil, uuid.Nil, time.Time{}, err
	}

	return claims.Account, scopes, tokenID, claims.ExpiresAt.Time, nil
}

func (t *Tokens) GetRefreshTTL() int64 {
	return t.refreshData.ttlSec
}
