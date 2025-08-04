package config

type DistributedCache struct {
	// Key Encryption Key (KEK) related configurations
	kekTTL int64

	// Data Encryption Key (DEK) related configurations
	dekDecTTL int64
	dekEncTTL int64

	// JSON Web Key (JWK) related configurations
	publicJWKTTL  int64
	privateJWKTTL int64
	publicJWKsTTL int64

	// Account related configurations
	accountUsernameTTL int64

	// Well-known URIs related configurations
	wellKnownOIDCConfigTTL int64

	// OAuth 2.0 related configurations
	oauthStateTTL int64
	oauthCodeTTL  int64
}

func (dc *DistributedCache) KEKTTL() int64 {
	return dc.kekTTL
}

func (dc *DistributedCache) DEKDecTTL() int64 {
	return dc.dekDecTTL
}

func (dc *DistributedCache) DEKEncTTL() int64 {
	return dc.dekEncTTL
}

func (dc *DistributedCache) PublicJWKTTL() int64 {
	return dc.publicJWKTTL
}

func (dc *DistributedCache) PrivateJWKTTL() int64 {
	return dc.privateJWKTTL
}

func (dc *DistributedCache) PublicJWKsTTL() int64 {
	return dc.publicJWKsTTL
}

func (dc *DistributedCache) AccountUsernameTTL() int64 {
	return dc.accountUsernameTTL
}

func (dc *DistributedCache) WellKnownOIDCConfigTTL() int64 {
	return dc.wellKnownOIDCConfigTTL
}

func (dc *DistributedCache) OAuthStateTTL() int64 {
	return dc.oauthStateTTL
}

func (dc *DistributedCache) OAuthCodeTTL() int64 {
	return dc.oauthCodeTTL
}

func NewDistributedCache(
	kekTTL, dekDecTTL, dekEncTTL, publicJWKTTL,
	privateJWKTTL, publicJWKsTTL, accountUsernameTTL,
	wellKnownOIDCConfigTTL, oauthStateTTL, oauthCodeTTL int64,
) DistributedCache {
	return DistributedCache{
		kekTTL:                 kekTTL,
		dekDecTTL:              dekDecTTL,
		dekEncTTL:              dekEncTTL,
		publicJWKTTL:           publicJWKTTL,
		privateJWKTTL:          privateJWKTTL,
		publicJWKsTTL:          publicJWKsTTL,
		accountUsernameTTL:     accountUsernameTTL,
		wellKnownOIDCConfigTTL: wellKnownOIDCConfigTTL,
		oauthStateTTL:          oauthStateTTL,
		oauthCodeTTL:           oauthCodeTTL,
	}
}
