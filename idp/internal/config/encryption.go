package config

import "encoding/json"

type EncryptionConfig struct {
	accountSecret string
	appSecret     string
	userSecret    string
	oldSecrets    []string
}

func NewEncryptionConfig(accountSecret, appSecret, userSecret, oldSecrets string) EncryptionConfig {
	var secretSlice []string
	if err := json.Unmarshal([]byte(oldSecrets), &secretSlice); err != nil {
		panic(err)
	}

	return EncryptionConfig{
		accountSecret: accountSecret,
		appSecret:     appSecret,
		userSecret:    userSecret,
		oldSecrets:    secretSlice,
	}
}

func (e *EncryptionConfig) AccountSecret() string {
	return e.accountSecret
}

func (e *EncryptionConfig) AppSecret() string {
	return e.appSecret
}

func (e *EncryptionConfig) UserSecret() string {
	return e.userSecret
}

func (e *EncryptionConfig) OldSecrets() []string {
	return e.oldSecrets
}
