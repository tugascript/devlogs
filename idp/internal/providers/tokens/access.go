package tokens

import (
	"crypto/ecdsa"
	"errors"
	"slices"

	"github.com/golang-jwt/jwt/v5"
)

func (t *Tokens) getAccessTokenPrivateKey(scopes []AccountScope) *ecdsa.PrivateKey {
	if slices.Contains(scopes, AccountScopeClientID) {
		return t.accountCredentialsData.curKeyPair.privateKey
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
		scopes:         opts.Scopes,
	})
}

func (t *Tokens) VerifyAccessToken(token string) (AccountClaims, []AccountScope, error) {
	claims, err := verifyToken(token, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractUserTokenKID(token)
		if err != nil {
			return ecdsa.PublicKey{}, err
		}

		if t.accessData.prevPubKey != nil && t.accessData.prevPubKey.kid == kid {
			return t.accessData.prevPubKey.publicKey, nil
		}
		if t.accountCredentialsData.prevPubKey != nil && t.accountCredentialsData.prevPubKey.kid == kid {
			return t.accountCredentialsData.prevPubKey.publicKey, nil
		}
		if t.accessData.curKeyPair.kid == kid {
			return t.accessData.curKeyPair.publicKey, nil
		}
		if t.accountCredentialsData.curKeyPair.kid == kid {
			return t.accountCredentialsData.curKeyPair.publicKey, nil
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

func (t *Tokens) GetAccountCredentialsTTL() int64 {
	return t.accountCredentialsData.ttlSec
}
