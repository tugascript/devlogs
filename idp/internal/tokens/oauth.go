package tokens

import "github.com/golang-jwt/jwt/v5"

func (t *Tokens) CreateOAuthToken(opts AccountTokenOptions) (string, error) {
	return t.createToken(tokenOptions{
		privateKey:     t.oauthData.privateKey,
		ttlSec:         t.oauthData.ttlSec,
		accountID:      opts.ID,
		accountVersion: opts.Version,
		accountEmail:   opts.Email,
	})
}

func (t *Tokens) VerifyOAuthToken(token string) (AccountClaims, error) {
	claims := tokenClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return t.oauthData.publicKey, nil
	})
	return claims.Account, err
}

func (t *Tokens) GetOAuthTtl() int64 {
	return t.oauthData.ttlSec
}
