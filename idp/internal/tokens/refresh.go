package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func (t *Tokens) CreateRefreshToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(tokenOptions{
		privateKey:     t.refreshData.privateKey,
		ttlSec:         t.refreshData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
	})
}

func (t *Tokens) VerifyRefreshToken(token string) (AccountClaims, uuid.UUID, error) {
	claims := tokenClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return t.refreshData.publicKey, nil
	})
	if err != nil {
		return claims.Account, uuid.Nil, err
	}

	id, err := uuid.Parse(claims.ID)
	if err != nil {
		return claims.Account, uuid.Nil, err
	}

	return claims.Account, id, err
}

func (t *Tokens) GetRefreshTtl() int64 {
	return t.refreshData.ttlSec
}
