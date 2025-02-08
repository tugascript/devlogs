package params

type OAuthURLParams struct {
	Provider string `validate:"oneof=facebook github google microsoft"`
}
