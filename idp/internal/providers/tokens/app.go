package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AppTokenOptions struct {
	AppID    uuid.UUID
	AppSlug  string
	Audience string
}

type appTokenClaims struct {
	GrantType          string `json:"gty"`
	AuthorizationParty string `json:"azp"`
	jwt.RegisteredClaims
}

func (t *Tokens) CreateAppToken(opts AppTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.appData.ttlSec)))
	appIDString := opts.AppID.String()
	token := jwt.NewWithClaims(&jwt.SigningMethodECDSA{}, appTokenClaims{
		GrantType:          "client-credentials",
		AuthorizationParty: appIDString,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    fmt.Sprintf("https://%s.%s", opts.AppSlug, t.backendDomain),
			Audience:  jwt.ClaimStrings{opts.Audience},
			Subject:   appIDString,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = t.appData.curKeyPair.kid.String()
	return token.SignedString(t.appData.curKeyPair.privateKey)
}

func (t *Tokens) VerifyAppToken(token string) (uuid.UUID, error) {
	claims := appTokenClaims{}
	_, err := jwt.ParseWithClaims(token, &claims, func(token *jwt.Token) (interface{}, error) {
		kid := token.Header["kid"].(string)
		if kid != t.appData.curKeyPair.kid.String() {
			return nil, jwt.ErrInvalidKey
		}
		return t.appData.curKeyPair.publicKey, nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	sub, err := uuid.Parse(claims.Subject)
	if err != nil {
		return uuid.Nil, err
	}

	return sub, nil
}
