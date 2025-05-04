package tokens

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AppClaims struct {
	ID       int32  `json:"id"`
	ClientID string `json:"client_id"`
}

type appTokenClaims struct {
	App AppClaims `json:"app"`
	jwt.RegisteredClaims
}

type AppTokenOptions struct {
	ID       int32
	ClientID string
	Username string
}

func (t *Tokens) CreateAppToken(opts AppTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.appsData.ttlSec)))
	aud := fmt.Sprintf("https://%s.%s", opts.Username, t.frontendDomain)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, appTokenClaims{
		App: AppClaims{
			ID:       opts.ID,
			ClientID: opts.ClientID,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.frontendDomain,
			Audience:  jwt.ClaimStrings{aud},
			Subject:   opts.Username,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = t.appsData.curKeyPair.kid
	return token.SignedString(t.appsData.curKeyPair.privateKey)
}

func (t *Tokens) VerifyAppToken(token string) (int32, error) {
	claims := new(appTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		kid, err := extractTokenKID(token)
		if err != nil {
			return nil, err
		}

		if t.appsData.prevPubKey != nil && t.appsData.prevPubKey.kid == kid {
			return t.appsData.prevPubKey.publicKey, nil
		}
		if t.appsData.curKeyPair.kid == kid {
			return t.appsData.curKeyPair.publicKey, nil
		}

		return nil, fmt.Errorf("no key found for kid %s", kid)
	}); err != nil {
		return 0, err
	}

	return claims.App.ID, nil
}
