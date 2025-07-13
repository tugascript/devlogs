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

type AppScope = string

const AppScopeAccountUserAuth AppScope = "account:users:authenticate"

type AppClaims struct {
	ClientID string `json:"client_id"`
	Version  int32  `json:"version"`
}

type appTokenClaims struct {
	AppClaims
	jwt.RegisteredClaims
	Scope string `json:"scope"`
}

type AppTokenOptions struct {
	ClientID        string
	Version         int32
	AccountUsername string
}

func (t *Tokens) CreateAppToken(opts AppTokenOptions) *jwt.Token {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(t.appsTTL)))
	audAndIss := fmt.Sprintf("https://%s.%s", opts.AccountUsername, t.backendDomain)
	return jwt.NewWithClaims(jwt.SigningMethodES256, appTokenClaims{
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
		Scope: AppScopeAccountUserAuth,
	})
}

func (t *Tokens) VerifyAppToken(token string, getPublicJWK GetPublicJWK) (AppClaims, error) {
	claims := new(appTokenClaims)

	if _, err := jwt.ParseWithClaims(token, claims, buildVerifyKey(utils.SupportedCryptoSuiteES256, getPublicJWK)); err != nil {
		return AppClaims{}, err
	}

	if len(claims.Audience) < 1 {
		return AppClaims{}, errors.New("invalid audience")
	}

	aud := claims.Audience[0]
	audSlice := strings.Split(aud, ".")
	if len(audSlice) < 2 {
		return AppClaims{}, errors.New("invalid audience")
	}

	if !utils.IsValidSubdomain(strings.Replace(audSlice[0], "https://", "", 1)) {
		return AppClaims{}, errors.New("invalid account username")
	}

	return claims.AppClaims, nil
}

func (t *Tokens) GetAppTTL() int64 {
	return t.appsTTL
}
