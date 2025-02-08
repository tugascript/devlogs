package params

type OAuthURLParams struct {
	Provider string `validate:"oneof=facebook github google microsoft"`
}

type OAuthCallbackQueryParams struct {
	Code  string `validate:"required,min=1"`
	State string `validate:"required,min=1,hexadecimal"`
}
