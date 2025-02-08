package params

type AccountCredentialsURLParams struct {
	ClientID string `validate:"required,min=22,max=22,alphanum"`
}
