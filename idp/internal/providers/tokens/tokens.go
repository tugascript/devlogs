package tokens

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type SupportedCryptoSuite string

const (
	SupportedCryptoSuiteEd25519 SupportedCryptoSuite = "EdDSA"
	SupportedCryptoSuiteES256   SupportedCryptoSuite = "ES256"
)

type PreviousPublicKey struct {
	publicKey ed25519.PublicKey
	kid       string
}

type TokenKeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	kid        string
}

type TokenSecretData struct {
	curKeyPair TokenKeyPair
	prevPubKey *PreviousPublicKey
	ttlSec     int64
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

	return publicKeyValue, utils.ExtractKeyID(publicKeyValue)
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

type PreviousEs256PublicKey struct {
	publicKey *ecdsa.PublicKey
	kid       string
}

type Es256TokenKeyPair struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	kid        string
}

type Es256TokenSecretData struct {
	curKeyPair Es256TokenKeyPair
	prevPubKey *PreviousEs256PublicKey
	ttlSec     int64
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
		kid:        utils.ExtractKeyID(publicKeyValue),
	}
}

func extractEs256PublicKey(publicKey string) (*ecdsa.PublicKey, string) {
	publicKeyBlock, _ := pem.Decode([]byte(publicKey))
	if publicKeyBlock == nil || publicKeyBlock.Type != "PUBLIC KEY" {
		panic("Invalid public key")
	}

	publicKeyData, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		panic(err)
	}

	pubKey, ok := publicKeyData.(*ecdsa.PublicKey)
	if !ok {
		panic("Invalid public key")
	}

	publicKeyValue, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		panic(err)
	}

	return pubKey, utils.ExtractKeyID(publicKeyValue)
}

func newTokenSecretData(
	publicKey,
	privateKey,
	previousPublicKey string,
	ttlSec int64,
) TokenSecretData {
	curKeyPair := extractEd25519PublicPrivateKeyPair(publicKey, privateKey)

	if previousPublicKey != "" {
		pubKey, kid := extractEd25519PublicKey(previousPublicKey)
		return TokenSecretData{
			curKeyPair: curKeyPair,
			prevPubKey: &PreviousPublicKey{publicKey: pubKey, kid: kid},
			ttlSec:     ttlSec,
		}
	}

	return TokenSecretData{
		curKeyPair: curKeyPair,
		ttlSec:     ttlSec,
	}
}

func newEs256TokenSecretData(privateKey, previousPublicKey string, ttlSec int64) Es256TokenSecretData {
	curKeyPair := extractEs256KeyPair(privateKey)

	if previousPublicKey != "" {
		prevPubKey, kid := extractEs256PublicKey(previousPublicKey)
		return Es256TokenSecretData{
			curKeyPair: curKeyPair,
			prevPubKey: &PreviousEs256PublicKey{publicKey: prevPubKey, kid: kid},
			ttlSec:     ttlSec,
		}
	}

	return Es256TokenSecretData{
		curKeyPair: curKeyPair,
		ttlSec:     ttlSec,
	}
}

type Tokens struct {
	frontendDomain         string
	backendDomain          string
	accessData             Es256TokenSecretData
	accountCredentialsData Es256TokenSecretData
	refreshData            TokenSecretData
	confirmationData       TokenSecretData
	resetData              TokenSecretData
	oauthData              TokenSecretData
	twoFAData              TokenSecretData
	jwks                   []utils.ES256JWK
}

func NewTokens(
	accessCfg,
	accountCredentialsCfg,
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
		accessCfg.PreviousPublicKey(),
		accessCfg.TtlSec(),
	)
	accountKeysData := newEs256TokenSecretData(
		accountCredentialsCfg.PrivateKey(),
		accountCredentialsCfg.PreviousPublicKey(),
		accountCredentialsCfg.TtlSec(),
	)

	jwks := []utils.ES256JWK{
		utils.EncodeP256Jwk(accountKeysData.curKeyPair.publicKey, accountKeysData.curKeyPair.kid),
		utils.EncodeP256Jwk(accessData.curKeyPair.publicKey, accessData.curKeyPair.kid),
	}

	if accountKeysData.prevPubKey != nil {
		jwks = append(jwks, utils.EncodeP256Jwk(
			accountKeysData.prevPubKey.publicKey,
			accessData.prevPubKey.kid,
		))
	}
	if accessData.prevPubKey != nil {
		jwks = append(jwks, utils.EncodeP256Jwk(
			accessData.prevPubKey.publicKey,
			accessData.prevPubKey.kid,
		))
	}

	return &Tokens{
		accessData:             accessData,
		accountCredentialsData: accountKeysData,
		refreshData: newTokenSecretData(
			refreshCfg.PublicKey(),
			refreshCfg.PrivateKey(),
			refreshCfg.PreviousPublicKey(),
			refreshCfg.TtlSec(),
		),
		confirmationData: newTokenSecretData(
			confirmationCfg.PublicKey(),
			confirmationCfg.PrivateKey(),
			confirmationCfg.PreviousPublicKey(),
			confirmationCfg.TtlSec(),
		),
		resetData: newTokenSecretData(
			resetCfg.PublicKey(),
			resetCfg.PrivateKey(),
			resetCfg.PreviousPublicKey(),
			resetCfg.TtlSec(),
		),
		oauthData: newTokenSecretData(
			oauthCfg.PublicKey(),
			oauthCfg.PrivateKey(),
			oauthCfg.PreviousPublicKey(),
			oauthCfg.TtlSec(),
		),
		twoFAData: newTokenSecretData(
			twoFACfg.PublicKey(),
			twoFACfg.PrivateKey(),
			twoFACfg.PreviousPublicKey(),
			twoFACfg.TtlSec(),
		),
		frontendDomain: frontendDomain,
		backendDomain:  backendDomain,
		jwks:           jwks,
	}
}

func (t *Tokens) JWKs() []utils.ES256JWK {
	return t.jwks
}

func extractUserTokenKID(token *jwt.Token) (string, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", jwt.ErrInvalidKey
	}

	return kid, nil
}
