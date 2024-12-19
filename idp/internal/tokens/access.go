package tokens

import (
	"github.com/golang-jwt/jwt/v5"
)

func (t *Tokens) CreateAccessToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(tokenOptions{
		privateKey:     t.accessData.privateKey,
		ttlSec:         t.accessData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
	})
}

func (t *Tokens) VerifyAccessToken(token string) (AccountClaims, error) {
	claims := tokenClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return t.accessData.publicKey, nil
	})
	return claims.Account, err
}

func (t *Tokens) GetAccessTtl() int64 {
	return t.accessData.ttlSec
}
