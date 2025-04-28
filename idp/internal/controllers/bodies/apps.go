package bodies

type CreateAppBody struct {
	Name string `json:"name" validate:"required,max=50,min=3,alphanum"`
}

type UpdateAppBody struct {
	Name           string   `json:"name" validate:"required,max=50,min=3,alphanum"`
	CallbackUris   []string `json:"callback_uris" validate:"required,url"`
	LogoutUris     []string `json:"logout_uris" validate:"required,url"`
	Scopes         []string `json:"scopes" validate:"required,oneof=email name birthday location gender"`
	Providers      []string `json:"providers" validate:"required,oneof=email_password client_credentials github google facebook apple microsoft"`
	IDTokenTtl     int32    `json:"id_token_ttl" validate:"required,gte=30,lte=2592000"` // 30 secs to 30 days
	JwtCryptoSuite string   `json:"jwt_crypto_suite" validate:"required,oneof=EdDSA ES256"`
}
