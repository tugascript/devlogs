package config

type SingleJwtConfig struct {
	publicKey  string
	privateKey string
	ttlSec     int64
	kid        string
}

func NewSingleJwtConfig(publicKey, privateKey, kid string, ttlSec int64) SingleJwtConfig {
	return SingleJwtConfig{
		publicKey:  publicKey,
		privateKey: privateKey,
		ttlSec:     ttlSec,
		kid:        kid,
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

func (s *SingleJwtConfig) KID() string {
	return s.kid
}

type TokensConfig struct {
	access      SingleJwtConfig
	accountKeys SingleJwtConfig
	refresh     SingleJwtConfig
	confirm     SingleJwtConfig
	reset       SingleJwtConfig
	oAuth       SingleJwtConfig
	twoFA       SingleJwtConfig
	app         SingleJwtConfig
}

func NewTokensConfig(
	access SingleJwtConfig,
	accountKeys SingleJwtConfig,
	refresh SingleJwtConfig,
	confirm SingleJwtConfig,
	oAuth SingleJwtConfig,
	twoFA SingleJwtConfig,
	app SingleJwtConfig,
) TokensConfig {
	return TokensConfig{
		access:      access,
		accountKeys: accountKeys,
		refresh:     refresh,
		confirm:     confirm,
		oAuth:       oAuth,
		twoFA:       twoFA,
		app:         app,
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

func (t *TokensConfig) App() SingleJwtConfig {
	return t.app
}
