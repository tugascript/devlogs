package tokens

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type TokenKeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	kid        string
}

type TokenSecretData struct {
	curKeyPair  TokenKeyPair
	prevKeyPair *TokenKeyPair
	ttlSec      int64
}

func extractKeyID(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	return utils.Base62Encode(hash[:16])
}

func extractEd25519PublicKey(publicKey string) (ed25519.PublicKey, string) {
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

	return publicKeyValue, extractKeyID(publicKeyValue)
}

func extractEd25519PrivateKey(privateKey string) ed25519.PrivateKey {
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

	return privateKeyValue
}

func extractEd25519PublicPrivateKeyPair(publicKey, privateKey string) TokenKeyPair {
	pubKey, kid := extractEd25519PublicKey(publicKey)
	return TokenKeyPair{
		publicKey:  pubKey,
		privateKey: extractEd25519PrivateKey(privateKey),
		kid:        kid,
	}
}

type Es256TokenKeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	kid        string
}

type Es256TokenSecretData struct {
	curKeyPair  Es256TokenKeyPair
	prevKeyPair *Es256TokenKeyPair
	ttlSec      int64
}

func extractEs256KeyPair(privateKey string) Es256TokenKeyPair {
	privateKeyBlock, _ := pem.Decode([]byte(privateKey))
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		panic("Invalid private key")
	}

	privateKeyData, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		privateKeyData, err = x509.ParseECPrivateKey(privateKeyBlock.Bytes)
		if err != nil {
			panic(err)
		}
	}

	privateKeyValue, ok := privateKeyData.(*ecdsa.PrivateKey)
	if !ok {
		panic("Invalid private key")
	}

	publicKeyValue, err := x509.MarshalPKIXPublicKey(&privateKeyValue.PublicKey)
	if err != nil {
		panic(err)
	}

	return Es256TokenKeyPair{
		privateKey: privateKeyValue,
		publicKey:  &privateKeyValue.PublicKey,
		kid:        extractKeyID(publicKeyValue),
	}
}

func newTokenSecretData(
	publicKey,
	privateKey string,
	ttlSec int64,
	prevPublicKey,
	prevPrivateKey *string,
) TokenSecretData {
	curKeyPair := extractEd25519PublicPrivateKeyPair(publicKey, privateKey)

	if prevPublicKey != nil && prevPrivateKey != nil {
		prevKeyPair := extractEd25519PublicPrivateKeyPair(*prevPublicKey, *prevPrivateKey)
		return TokenSecretData{
			curKeyPair:  curKeyPair,
			prevKeyPair: &prevKeyPair,
			ttlSec:      ttlSec,
		}
	}

	return TokenSecretData{
		curKeyPair: curKeyPair,
		ttlSec:     ttlSec,
	}
}

func newEs256TokenSecretData(privateKey string, ttlSec int64, prevPrivateKey *string) Es256TokenSecretData {
	curKeyPair := extractEs256KeyPair(privateKey)

	if prevPrivateKey != nil {
		prevKeyPair := extractEs256KeyPair(*prevPrivateKey)
		return Es256TokenSecretData{
			curKeyPair:  curKeyPair,
			prevKeyPair: &prevKeyPair,
			ttlSec:      ttlSec,
		}
	}

	return Es256TokenSecretData{
		curKeyPair: curKeyPair,
		ttlSec:     ttlSec,
	}
}

type Tokens struct {
	frontendDomain   string
	backendDomain    string
	accessData       Es256TokenSecretData
	accountKeysData  Es256TokenSecretData
	refreshData      TokenSecretData
	confirmationData TokenSecretData
	resetData        TokenSecretData
	oauthData        TokenSecretData
	twoFAData        TokenSecretData
	jwks             []utils.P256JWK
}

func NewTokens(
	accessCfg,
	accountKeysCfg,
	refreshCfg,
	confirmationCfg,
	resetCfg,
	oauthCfg,
	twoFACfg config.SingleJwtConfig,
	frontendDomain,
	backendDomain string,
) *Tokens {
	accessData := newEs256TokenSecretData(
		accessCfg.PrivateKey(),
		accessCfg.TtlSec(),
		nil,
	)
	accountKeysData := newEs256TokenSecretData(
		accountKeysCfg.PrivateKey(),
		accountKeysCfg.TtlSec(),
		nil,
	)

	jwks := []utils.P256JWK{
		utils.EncodeP256Jwk(accountKeysData.curKeyPair.publicKey, accountKeysData.curKeyPair.kid),
		utils.EncodeP256Jwk(accessData.curKeyPair.publicKey, accessData.curKeyPair.kid),
	}

	if accountKeysData.prevKeyPair != nil {
		jwks = append(jwks, utils.EncodeP256Jwk(
			accountKeysData.prevKeyPair.publicKey,
			accessData.prevKeyPair.kid,
		))
	}
	if accessData.prevKeyPair != nil {
		jwks = append(jwks, utils.EncodeP256Jwk(
			accessData.prevKeyPair.publicKey,
			accessData.prevKeyPair.kid,
		))
	}

	return &Tokens{
		accessData:      accessData,
		accountKeysData: accountKeysData,
		refreshData: newTokenSecretData(
			refreshCfg.PublicKey(),
			refreshCfg.PrivateKey(),
			refreshCfg.TtlSec(),
			nil,
			nil,
		),
		confirmationData: newTokenSecretData(
			confirmationCfg.PublicKey(),
			confirmationCfg.PrivateKey(),
			confirmationCfg.TtlSec(),
			nil,
			nil,
		),
		resetData: newTokenSecretData(
			resetCfg.PublicKey(),
			resetCfg.PrivateKey(),
			resetCfg.TtlSec(),
			nil,
			nil,
		),
		oauthData: newTokenSecretData(
			oauthCfg.PublicKey(),
			oauthCfg.PrivateKey(),
			oauthCfg.TtlSec(),
			nil,
			nil,
		),
		twoFAData: newTokenSecretData(
			twoFACfg.PublicKey(),
			twoFACfg.PrivateKey(),
			twoFACfg.TtlSec(),
			nil,
			nil,
		),
		frontendDomain: frontendDomain,
		backendDomain:  backendDomain,
		jwks:           jwks,
	}
}

func (t *Tokens) JWKs() []utils.P256JWK {
	return t.jwks
}

func extractUserTokenKID(token *jwt.Token) (string, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", jwt.ErrInvalidKey
	}

	return kid, nil
}
