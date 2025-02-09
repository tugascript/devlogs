package vault

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/jpeg"
	"strconv"

	infisical "github.com/infisical/go-sdk"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const topsBasePath = "auth/totps"

func generateTotpKey(backendDomain, path, email string) (*otp.Key, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      fmt.Sprintf("%s/%s", backendDomain, path),
		AccountName: email,
	})
	if err != nil {
		return nil, err
	}

	return key, nil
}

func base64EncodeKeyQRCode(key *otp.Key) (string, error) {
	img, err := key.Image(200, 200)
	if err != nil {
		return "", err
	}

	var imgBuf bytes.Buffer
	if err := jpeg.Encode(&imgBuf, img, &jpeg.Options{Quality: 90}); err != nil {
		return "", err
	}

	base64Img := base64.StdEncoding.EncodeToString(imgBuf.Bytes())
	return fmt.Sprintf("data:image/jpeg;base64,%s", base64Img), nil
}

func (v *Vault) GenerateAccountTotpKey(accountId int, email string) (string, error) {
	key, err := generateTotpKey(v.backendDomain, "", email)
	if err != nil {
		return "", err
	}

	if _, err := v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   strconv.Itoa(accountId),
		SecretPath:  fmt.Sprintf("%s/accounts", topsBasePath),
		SecretValue: key.Secret(),
		Environment: v.env,
	}); err != nil {
		return "", err
	}

	img64, err := base64EncodeKeyQRCode(key)
	if err != nil {
		return "", err
	}

	return img64, nil
}

func (v *Vault) VerifyAccountTotpKey(accountId int, code string) (bool, error) {
	secret, err := v.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretPath:  fmt.Sprintf("%s/accounts", topsBasePath),
		SecretKey:   strconv.Itoa(accountId),
		Environment: v.env,
	})
	if err != nil {
		return false, err
	}

	valid := totp.Validate(code, secret.SecretValue)
	return valid, nil
}
