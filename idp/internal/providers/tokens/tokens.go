package tokens

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type TokenKeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	kid        uuid.UUID
}

type TokenSecretData struct {
	curKeyPair  TokenKeyPair
	prevKeyPair *TokenKeyPair
	ttlSec      int64
}

func extractEd25519PublicKey(publicKey string) ed25519.PublicKey {
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

	return publicKeyValue
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

func extractEd25519PublicPrivateKeyPair(
	publicKey,
	privateKey string,
	keyID uuid.UUID,
) TokenKeyPair {
	return TokenKeyPair{
		publicKey:  extractEd25519PublicKey(publicKey),
		privateKey: extractEd25519PrivateKey(privateKey),
		kid:        keyID,
	}
}

type Es256TokenKeyPair struct {
	privateKey ecdsa.PrivateKey
	publicKey  ecdsa.PublicKey
	kid        uuid.UUID
}

type Es256TokenSecretData struct {
	curKeyPair  Es256TokenKeyPair
	prevKeyPair *Es256TokenKeyPair
	ttlSec      int64
}

func extractEs256KeyPair(privateKey string, keyID uuid.UUID) Es256TokenKeyPair {
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

	return Es256TokenKeyPair{
		privateKey: *privateKeyValue,
		publicKey:  privateKeyValue.PublicKey,
		kid:        keyID,
	}
}

func newTokenSecretData(
	publicKey,
	privateKey string,
	ttlSec int64,
	keyID uuid.UUID,
	prevPublicKey,
	prevPrivateKey *string,
	prevKeyID *uuid.UUID,
) TokenSecretData {
	curKeyPair := extractEd25519PublicPrivateKeyPair(publicKey, privateKey, keyID)

	if prevPublicKey != nil && prevPrivateKey != nil && prevKeyID != nil {
		prevKeyPair := extractEd25519PublicPrivateKeyPair(*prevPublicKey, *prevPrivateKey, *prevKeyID)
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

func newEs256TokenSecretData(
	privateKey string,
	ttlSec int64,
	keyID uuid.UUID,
	prevPrivateKey *string,
	prevKeyId *uuid.UUID,
) Es256TokenSecretData {
	curKeyPair := extractEs256KeyPair(privateKey, keyID)

	if prevPrivateKey != nil && prevKeyId != nil {
		prevKeyPair := extractEs256KeyPair(*prevPrivateKey, *prevKeyId)
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
	appData          Es256TokenSecretData
	jwks             []utils.P256JWK
}

func NewTokens(
	accessCfg,
	accountKeysCfg,
	refreshCfg,
	confirmationCfg,
	resetCfg,
	oauthCfg,
	twoFACfg,
	appCfg config.SingleJwtConfig,
	frontendDomain,
	backendDomain string,
) *Tokens {
	accessData := newEs256TokenSecretData(
		accessCfg.PrivateKey(),
		accessCfg.TtlSec(),
		uuid.MustParse(accessCfg.KID()),
		nil,
		nil,
	)
	accountKeysData := newEs256TokenSecretData(
		accountKeysCfg.PrivateKey(),
		accountKeysCfg.TtlSec(),
		uuid.MustParse(accessCfg.KID()),
		nil,
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
			uuid.MustParse(refreshCfg.KID()),
			nil,
			nil,
			nil,
		),
		confirmationData: newTokenSecretData(
			confirmationCfg.PublicKey(),
			confirmationCfg.PrivateKey(),
			confirmationCfg.TtlSec(),
			uuid.MustParse(confirmationCfg.KID()),
			nil,
			nil,
			nil,
		),
		resetData: newTokenSecretData(
			resetCfg.PublicKey(),
			resetCfg.PrivateKey(),
			resetCfg.TtlSec(),
			uuid.MustParse(resetCfg.KID()),
			nil,
			nil,
			nil,
		),
		oauthData: newTokenSecretData(
			oauthCfg.PublicKey(),
			oauthCfg.PrivateKey(),
			oauthCfg.TtlSec(),
			uuid.MustParse(oauthCfg.KID()),
			nil,
			nil,
			nil,
		),
		twoFAData: newTokenSecretData(
			twoFACfg.PublicKey(),
			twoFACfg.PrivateKey(),
			twoFACfg.TtlSec(),
			uuid.MustParse(twoFACfg.KID()),
			nil,
			nil,
			nil,
		),
		appData: newEs256TokenSecretData(
			appCfg.PrivateKey(),
			appCfg.TtlSec(),
			uuid.MustParse(appCfg.KID()),
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

func extractUserTokenKID(token *jwt.Token) (uuid.UUID, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return uuid.Nil, jwt.ErrInvalidKey
	}

	return uuid.Parse(kid)
}
