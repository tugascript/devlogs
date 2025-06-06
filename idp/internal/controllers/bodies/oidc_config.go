package bodies

type OIDCConfigBody struct {
	Claims         []string `json:"claims" validate:"required,dive,oneof=name given_name family_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo phone_number address"`
	Scopes         []string `json:"scopes" validate:"required,dive,oneof=openid profile email address phone"`
	JwtCryptoSuite string   `json:"jwt_crypto_suite" validate:"required,oneof=ES256 EdDSA"`
}
