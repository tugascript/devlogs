package vault

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	infisical "github.com/infisical/go-sdk"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const kmsBasePath = "auth/jwt/keys"

type Ed25519KeyPair struct {
	Kid       uuid.UUID
	PublicKey utils.Ed25519JWK
}

type Es256KeyPair struct {
	Kid       uuid.UUID
	PublicKey utils.P256JWK
}

func (v *Vault) GenerateEd25519KeyPair(accountId int) (Ed25519KeyPair, error) {
	var keyPair Ed25519KeyPair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return keyPair, err
	}

	kid, err := uuid.NewRandom()
	if err != nil {
		return keyPair, err
	}
	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return keyPair, err
	}

	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   kid.String(),
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, accountId),
		SecretValue: privKeyBase64,
		Environment: v.env,
	})

	keyPair = Ed25519KeyPair{
		Kid:       kid,
		PublicKey: utils.EncodeEd25519Jwk(pub, kid),
	}
	return keyPair, nil
}

func (v *Vault) GetEd25519PrivateKey(accountId int, kid uuid.UUID) (ed25519.PrivateKey, error) {
	secret, err := v.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretPath:  fmt.Sprintf("%s/accounts/%d/%s", kmsBasePath, accountId, kid.String()),
		Environment: v.env,
	})
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(secret.SecretValue)
	if err != nil {
		return nil, err
	}

	privateKeyData, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyData.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

	return privateKey, nil
}

func (v *Vault) GenerateEs256KeyPair(accountId int) (Es256KeyPair, error) {
	var keyPair Es256KeyPair
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keyPair, err
	}

	kid, err := uuid.NewRandom()
	if err != nil {
		return keyPair, err
	}

	privKey, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return keyPair, err
	}

	privKeyBase64 := base64.StdEncoding.EncodeToString(privKey)
	v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   kid.String(),
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, accountId),
		SecretValue: privKeyBase64,
		Environment: v.env,
	})

	keyPair = Es256KeyPair{
		Kid:       kid,
		PublicKey: utils.EncodeP256Jwk(priv.PublicKey, kid),
	}
	return keyPair, nil
}

func (v *Vault) GetEs256PrivateKey(accountId int, kid uuid.UUID) (*ecdsa.PrivateKey, error) {
	secret, err := v.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretPath:  fmt.Sprintf("%s/accounts/%d/%s", kmsBasePath, accountId, kid.String()),
		Environment: v.env,
	})
	if err != nil {
		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(secret.SecretValue)
	if err != nil {
		return nil, err
	}

	privateKeyData, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, err
	}

	privateKey, ok := privateKeyData.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("invalid private key")
	}

	return privateKey, nil
}

func (v *Vault) DeleteKeyPair(accountId int, kid uuid.UUID) error {
	_, err := v.client.Secrets().Delete(infisical.DeleteSecretOptions{
		SecretKey:   kid.String(),
		SecretPath:  fmt.Sprintf("%s/accounts/%d", kmsBasePath, accountId),
		Environment: v.env,
	})
	return err
}
