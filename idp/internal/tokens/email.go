package tokens

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type EmailTokenType = string

const (
	EmailTokenConfirmation EmailTokenType = "confirmation"
	EmailTokenReset        EmailTokenType = "reset"
)

type emailTokenClaims struct {
	User AccountClaims
	Type EmailTokenType
	jwt.RegisteredClaims
}

type EmailTokenOptions struct {
	UserID      int32
	UserVersion int32
	UserEmail   string
	Type        string
}

func (t *Tokens) CreateEmailToken(opts EmailTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.emailData.ttlSec)))
	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, emailTokenClaims{
		User: AccountClaims{
			ID:      opts.UserID,
			Version: opts.UserVersion,
		},
		Type: opts.Type,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.iss,
			Audience:  jwt.ClaimStrings{t.iss},
			Subject:   opts.UserEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	return token.SignedString(t.emailData.privateKey)
}

func (t *Tokens) VerifyEmailToken(token string) (AccountClaims, EmailTokenType, error) {
	claims := emailTokenClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		return t.emailData.publicKey, nil
	})
	return claims.User, claims.Type, err
}
