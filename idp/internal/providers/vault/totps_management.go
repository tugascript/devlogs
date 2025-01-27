package vault

import (
	"fmt"
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

func (v *Vault) GenerateAccountTotpKey(accountId int, backendDomain, email string) (*otp.Key, error) {
	key, err := generateTotpKey(backendDomain, "", email)
	if err != nil {
		return nil, err
	}

	if _, err := v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey:   strconv.Itoa(accountId),
		SecretPath:  fmt.Sprintf("%s/accounts", topsBasePath),
		SecretValue: key.Secret(),
		Environment: v.env,
	}); err != nil {
		return nil, err
	}

	return key, nil
}

func (v *Vault) GenerateUserTotpKey(accountId, userId int, backendDomain, email string) (*otp.Key, error) {
	key, err := generateTotpKey(
		backendDomain,
		fmt.Sprintf("accounts/%d/auth/two-factor", accountId),
		email,
	)
	if err != nil {
		return nil, err
	}

	if _, err := v.client.Secrets().Create(infisical.CreateSecretOptions{
		SecretKey: strconv.Itoa(userId),
		SecretPath: fmt.Sprintf(
			"%s/accounts/%d/users",
			topsBasePath,
			accountId,
		),
		SecretValue: key.Secret(),
		Environment: v.env,
	}); err != nil {
		return nil, err
	}

	return key, nil
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

func (v *Vault) VerifyUserTotpKey(accountId, userId int, code string) (bool, error) {
	secret, err := v.client.Secrets().Retrieve(infisical.RetrieveSecretOptions{
		SecretPath:  fmt.Sprintf("%s/accounts/%d/users", topsBasePath, accountId),
		SecretKey:   strconv.Itoa(userId),
		Environment: v.env,
	})
	if err != nil {
		return false, err
	}

	valid := totp.Validate(code, secret.SecretValue)
	return valid, nil
}
