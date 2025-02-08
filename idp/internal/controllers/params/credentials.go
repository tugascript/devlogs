package params

type CredentialsURLParams struct {
	ClientID string `validate:"required,min=22,max=22,alphanum"`
}
