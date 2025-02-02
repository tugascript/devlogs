package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	ID      int32 `json:"id"`
	Version int32 `json:"version"`
}

type userTokenClaims struct {
	User UserClaims
	jwt.RegisteredClaims
}

type UserTokenOptions struct {
	Method          jwt.SigningMethod
	PrivateKey      interface{}
	KID             string
	TTLSec          int64
	AccountUsername string
	UserID          int32
	UserVersion     int32
	UserEmail       string
}

func (t *Tokens) CreateUserToken(opts UserTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.TTLSec)))
	iss := fmt.Sprintf(
		"https://%s.%s",
		opts.AccountUsername,
		t.frontendDomain,
	)
	token := jwt.NewWithClaims(opts.Method, userTokenClaims{
		User: UserClaims{
			ID:      opts.UserID,
			Version: opts.UserVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Audience:  jwt.ClaimStrings{iss},
			Subject:   opts.UserEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = opts.KID
	return token.SignedString(opts.PrivateKey)
}
