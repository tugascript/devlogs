package config

type SingleJwtConfig struct {
	publicKey  string
	privateKey string
	ttlSec     int64
}

func NewSingleJwtConfig(publicKey, privateKey string, ttlSec int64) SingleJwtConfig {
	return SingleJwtConfig{
		publicKey:  publicKey,
		privateKey: privateKey,
		ttlSec:     ttlSec,
	}
}

func (s *SingleJwtConfig) PublicKey() string {
	return s.publicKey
}

func (s *SingleJwtConfig) PrivateKey() string {
	return s.privateKey
}

func (s *SingleJwtConfig) TtlSec() int64 {
	return s.ttlSec
}

type TokensConfig struct {
	access      SingleJwtConfig
	accountKeys SingleJwtConfig
	refresh     SingleJwtConfig
	confirm     SingleJwtConfig
	reset       SingleJwtConfig
	oAuth       SingleJwtConfig
	twoFA       SingleJwtConfig
}

func NewTokensConfig(
	access SingleJwtConfig,
	accountKeys SingleJwtConfig,
	refresh SingleJwtConfig,
	confirm SingleJwtConfig,
	oAuth SingleJwtConfig,
	twoFA SingleJwtConfig,
) TokensConfig {
	return TokensConfig{
		access:      access,
		accountKeys: accountKeys,
		refresh:     refresh,
		confirm:     confirm,
		oAuth:       oAuth,
		twoFA:       twoFA,
	}
}

func (t *TokensConfig) Access() SingleJwtConfig {
	return t.access
}

func (t *TokensConfig) AccountKeys() SingleJwtConfig {
	return t.accountKeys
}

func (t *TokensConfig) Refresh() SingleJwtConfig {
	return t.refresh
}

func (t *TokensConfig) Confirm() SingleJwtConfig {
	return t.confirm
}

func (t *TokensConfig) Reset() SingleJwtConfig {
	return t.reset
}

func (t *TokensConfig) OAuth() SingleJwtConfig {
	return t.oAuth
}

func (t *TokensConfig) TwoFA() SingleJwtConfig {
	return t.twoFA
}
