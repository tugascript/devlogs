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

func NewDistributedCache(
	kekTTL, dekDecTTL, dekEncTTL, publicJWKTTL,
	privateJWKTTL, publicJWKsTTL, accountUsernameTTL,
	wellKnownOIDCConfigTTL int64,
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
	}
}
