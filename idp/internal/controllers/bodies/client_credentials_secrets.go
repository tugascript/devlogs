package bodies

type CreateCredentialsSecretBody struct {
	Algorithm string `json:"algorithm,omitempty" validate:"omitempty,oneof=ES256 EdDSA"`
}
