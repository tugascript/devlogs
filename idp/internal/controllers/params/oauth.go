package params

type OAuthQueryParams struct {
	ClientID        string `validate:"required,oneof=apple facebook github google microsoft"`
	ResponseType    string `validate:"required,oneof=code"`
	Challenge       string `validate:"required,min=1"`
	ChallengeMethod string `validate:"omitempty,oneof=plain s256 S256"`
	State           string `validate:"required,min=1"`
}
