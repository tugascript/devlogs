package tokens

import "github.com/golang-jwt/jwt/v5"

type AccountTokenOptions struct {
	ID      int32
	Version int32
	Email   string
}

type AccountClaims struct {
	ID      int32
	Version int32
}

type tokenClaims struct {
	Account AccountClaims
	jwt.RegisteredClaims
}
