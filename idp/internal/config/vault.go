package config

type VaultConfig struct {
	url           string
	clientID      string
	clientSecret  string
	env           string
	backendDomain string
}

func NewVaultConfig(url, clientID, clientSecret, backendDomain, env string) VaultConfig {
	return VaultConfig{
		url:           url,
		clientID:      clientID,
		clientSecret:  clientSecret,
		backendDomain: backendDomain,
		env:           env,
	}
}

func (v *VaultConfig) Url() string {
	return v.url
}

func (v *VaultConfig) ClientID() string {
	return v.clientID
}

func (v *VaultConfig) ClientSecret() string {
	return v.clientSecret
}

func (v *VaultConfig) Env() string {
	return v.env
}
