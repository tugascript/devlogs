package tokens

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenSecretData struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	ttlSec     int64
}

func NewTokenSecretData(publicKey, privateKey string, ttlSec int64) TokenSecretData {
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	if publicKeyBlock == nil || publicKeyBlock.Type != "PUBLIC KEY" {
		panic("Invalid public key")
	}

	publicKeyData, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	publicKeyValue, ok := publicKeyData.(ed25519.PublicKey)
	if !ok {
		panic("Invalid public key")
	}

	privateKeyBlock, _ := pem.Decode([]byte(privateKey))
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		panic("Invalid private key")
	}

	privateKeyData, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	privateKeyValue, ok := privateKeyData.(ed25519.PrivateKey)
	if !ok {
		panic("Invalid private key")
	}

	return TokenSecretData{
		publicKey:  publicKeyValue,
		privateKey: privateKeyValue,
		ttlSec:     ttlSec,
	}
}

type Tokens struct {
	iss             string
	accessData      TokenSecretData
	refreshData     TokenSecretData
	emailData       TokenSecretData
	oauthData       TokenSecretData
	userAccessData  TokenSecretData
	userRefreshData TokenSecretData
	userEmailData   TokenSecretData
	userOauthData   TokenSecretData
}

func NewTokens(
	accessData,
	refreshData,
	emailData,
	oauthData,
	userAccessData,
	userRefreshData,
	userEmailData,
	userOauthData TokenSecretData,
	url string,
) *Tokens {
	return &Tokens{
		accessData:      accessData,
		refreshData:     refreshData,
		emailData:       emailData,
		oauthData:       oauthData,
		userAccessData:  userAccessData,
		userRefreshData: userRefreshData,
		userEmailData:   userEmailData,
		userOauthData:   userOauthData,
		iss:             url,
	}
}

type tokenOptions struct {
	privateKey     ed25519.PrivateKey
	ttlSec         int64
	accountID      int32
	accountVersion int32
	accountEmail   string
}

func (t *Tokens) createToken(opts tokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))
	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, tokenClaims{
		Account: AccountClaims{
			ID:      opts.accountID,
			Version: opts.accountVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.iss,
			Audience:  jwt.ClaimStrings{t.iss},
			Subject:   opts.accountEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	return token.SignedString(opts.privateKey)
}

type userTokenOptions struct {
	privateKey  ed25519.PrivateKey
	ttlSec      int64
	accountID   int32
	userID      int32
	userVersion int32
	userEmail   string
}

func (t *Tokens) createUserToken(opts userTokenOptions) (string, error) {
	now := time.Now()
	iat := jwt.NewNumericDate(now)
	exp := jwt.NewNumericDate(now.Add(time.Second * time.Duration(opts.ttlSec)))
	token := jwt.NewWithClaims(&jwt.SigningMethodEd25519{}, userTokenClaims{
		User: UserClaims{
			AccountID: opts.accountID,
			ID:        opts.userID,
			Version:   opts.userVersion,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    t.iss,
			Audience:  jwt.ClaimStrings{t.iss},
			Subject:   opts.userEmail,
			IssuedAt:  iat,
			NotBefore: iat,
			ExpiresAt: exp,
			ID:        uuid.NewString(),
		},
	})
	return token.SignedString(opts.privateKey)
}
