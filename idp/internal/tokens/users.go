package tokens

import "github.com/golang-jwt/jwt/v5"

type UserTokenOptions struct {
	AccountID int32
	ID        int32
	Version   int32
	Email     string
}

type UserClaims struct {
	AccountID int32
	ID        int32
	Version   int32
}

type userTokenClaims struct {
	User UserClaims
	jwt.RegisteredClaims
}
