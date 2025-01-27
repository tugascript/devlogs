package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	AppID   uuid.UUID
	ID      int32
	Version int32
}

type userTokenClaims struct {
	User UserClaims
	jwt.RegisteredClaims
}

type UserTokenOptions struct {
	Method      jwt.SigningMethod
	PrivateKey  interface{}
	KID         uuid.UUID
	TTLSec      int64
	AppID       uuid.UUID
	UserID      int32
	UserVersion int32
	UserEmail   string
}

func (t *Tokens) CreateUserToken(opts UserTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.TTLSec)))
	iss := fmt.Sprintf(
		"%s/api/v1/apps/%s",
		t.frontendDomain,
		opts.AppID.String(),
	)
	token := jwt.NewWithClaims(opts.Method, userTokenClaims{
		User: UserClaims{
			AppID:   opts.AppID,
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
	token.Header["kid"] = opts.KID.String()
	return token.SignedString(opts.PrivateKey)
}
