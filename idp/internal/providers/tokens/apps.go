package tokens

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AppClaims struct {
	ClientID string `json:"client_id"`
	Version  int32  `json:"version"`
}

type appTokenClaims struct {
	AppClaims
	jwt.RegisteredClaims
}

type AppTokenOptions struct {
	ClientID        string
	Version         int32
	AccountUsername string
}

func (t *Tokens) CreateAppToken(opts AppTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.appsData.ttlSec)))
	audAndIss := fmt.Sprintf("https://%s.%s", opts.AccountUsername, t.backendDomain)
	token := jwt.NewWithClaims(jwt.SigningMethodES256, appTokenClaims{
		AppClaims: AppClaims{
			ClientID: opts.ClientID,
			Version:  opts.Version,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    audAndIss,
			Audience:  jwt.ClaimStrings{audAndIss},
			Subject:   opts.ClientID,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	token.Header["kid"] = t.appsData.curKeyPair.kid
	return token.SignedString(t.appsData.curKeyPair.privateKey)
}

func (t *Tokens) VerifyAppToken(token string) (AppClaims, string, error) {
	claims := new(appTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (any, error) {
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
		return AppClaims{}, "", err
	}

	if len(claims.Audience) < 1 {
		return AppClaims{}, "", errors.New("invalid audience")
	}

	aud := claims.Audience[0]
	audSlice := strings.Split(aud, ".")
	if len(audSlice) < 2 {
		return AppClaims{}, "", errors.New("invalid audience")
	}

	accountUsername := strings.Replace(audSlice[0], "https://", "", 1)
	if !utils.IsValidSubdomain(accountUsername) {
		return AppClaims{}, "", errors.New("invalid account username")
	}

	return claims.AppClaims, accountUsername, nil
}
