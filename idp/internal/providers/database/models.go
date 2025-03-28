// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0

package database

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Account struct {
	ID            int32
	FirstName     string
	LastName      string
	Username      string
	Email         string
	Password      pgtype.Text
	Version       int32
	IsConfirmed   bool
	TwoFactorType string
	CreatedAt     pgtype.Timestamp
	UpdatedAt     pgtype.Timestamp
}

type AccountCredential struct {
	ID           int32
	AccountID    int32
	Scopes       []byte
	ClientID     string
	ClientSecret string
	CreatedAt    pgtype.Timestamp
	UpdatedAt    pgtype.Timestamp
}

type AccountTotp struct {
	ID            int32
	AccountID     int32
	Url           string
	Secret        string
	Dek           string
	RecoveryCodes []byte
	CreatedAt     pgtype.Timestamp
	UpdatedAt     pgtype.Timestamp
}

type App struct {
	ID             int32
	AccountID      int32
	Name           string
	ClientID       string
	ClientSecret   string
	Dek            string
	CallbackUris   []string
	LogoutUris     []string
	UserScopes     []byte
	AppProviders   []byte
	IDTokenTtl     int32
	JwtCryptoSuite string
	CreatedAt      pgtype.Timestamp
	UpdatedAt      pgtype.Timestamp
}

type AppKey struct {
	ID             int32
	AppID          int32
	AccountID      int32
	Name           string
	JwtCryptoSuite string
	PublicKey      []byte
	PrivateKey     string
	CreatedAt      pgtype.Timestamp
	UpdatedAt      pgtype.Timestamp
}

type AuthProvider struct {
	ID        int32
	Email     string
	Provider  string
	CreatedAt pgtype.Timestamp
	UpdatedAt pgtype.Timestamp
}

type BlacklistedToken struct {
	ID        uuid.UUID
	ExpiresAt pgtype.Timestamp
	CreatedAt pgtype.Timestamp
}

type User struct {
	ID            int32
	AccountID     int32
	Email         string
	Password      pgtype.Text
	Version       int32
	TwoFactorType string
	UserData      []byte
	CreatedAt     pgtype.Timestamp
	UpdatedAt     pgtype.Timestamp
}

type UserAuthProvider struct {
	ID        int32
	UserID    int32
	Email     string
	Provider  string
	AccountID int32
	CreatedAt pgtype.Timestamp
	UpdatedAt pgtype.Timestamp
}

type UserTotp struct {
	ID            int32
	UserID        int32
	Url           string
	Secret        string
	Dek           string
	RecoveryCodes []byte
	CreatedAt     pgtype.Timestamp
	UpdatedAt     pgtype.Timestamp
}
