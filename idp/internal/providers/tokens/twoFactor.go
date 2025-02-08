package tokens

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
)

func (t *Tokens) Create2FAToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(accountTokenOptions{
		method:         jwt.SigningMethodEdDSA,
		privateKey:     t.twoFAData.curKeyPair.privateKey,
		kid:            t.twoFAData.curKeyPair.kid,
		ttlSec:         t.twoFAData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
		scopes:         []AccountScope{AccountScope2FA},
	})
}

func (t *Tokens) Verify2FAToken(token string) (AccountClaims, []AccountScope, error) {
	claims, err := verifyToken(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractUserTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.twoFAData.prevKeyPair != nil && t.twoFAData.prevKeyPair.kid == kid {
			return t.twoFAData.prevKeyPair.publicKey, nil
		}
		if t.twoFAData.curKeyPair.kid == kid {
			return t.twoFAData.curKeyPair.publicKey, nil
		}

		return nil, errors.New("no key found for kid")
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

func (t *Tokens) Get2FATTL() int64 {
	return t.twoFAData.ttlSec
}
