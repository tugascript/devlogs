package tokens

import (
	"crypto/ecdsa"
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

func (t *Tokens) getAccessTokenPrivateKey(scopes []AccountScope) ecdsa.PrivateKey {
	if slices.Contains(scopes, AccountScopeClientID) {
		return t.accountKeysData.curKeyPair.privateKey
	}

	return t.accessData.curKeyPair.privateKey
}

func (t *Tokens) CreateAccessToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(accountTokenOptions{
		method:         jwt.SigningMethodES256,
		privateKey:     t.getAccessTokenPrivateKey(opts.Scopes),
		kid:            t.accessData.curKeyPair.kid,
		ttlSec:         t.accessData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
		audience:       opts.Audience,
		subject:        opts.Email,
		scopes:         opts.Scopes,
	})
}

func (t *Tokens) VerifyAccessToken(token string) (AccountClaims, []AccountScope, error) {
	claims, err := verifyToken(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractUserTokenKID(token)
		if err != nil {
			return ecdsa.PublicKey{}, err
		}

		if t.accessData.prevKeyPair != nil && t.accessData.prevKeyPair.kid == kid {
			return t.accessData.prevKeyPair.publicKey, nil
		}
		if t.accountKeysData.prevKeyPair != nil && t.accountKeysData.prevKeyPair.kid == kid {
			return t.accountKeysData.prevKeyPair.publicKey, nil
		}
		if t.accessData.curKeyPair.kid == kid {
			return t.accessData.curKeyPair.publicKey, nil
		}
		if t.accountKeysData.curKeyPair.kid == kid {
			return t.accountKeysData.curKeyPair.publicKey, nil
		}

		return ecdsa.PublicKey{}, errors.New("no key found for kid")
	})
	if err != nil {
		return AccountClaims{}, nil, err
	}

	scopes, err := splitAccountScopes(claims.Scopes)
	if err != nil {
		return AccountClaims{}, nil, err
	}

	return claims.Account, scopes, nil
}

func (t *Tokens) GetAccessTTL() int64 {
	return t.accessData.ttlSec
}

func (t *Tokens) GetAccountKeysTTL() int64 {
	return t.accountKeysData.ttlSec
}
