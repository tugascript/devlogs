package bodies

type OAuthCodeLoginBody struct {
	ClientID     string `json:"client_id" validate:"required,oneof=apple facebook github google microsoft"`
	GrantType    string `json:"grant_type" validate:"required,eq=authorization_code"`
	Code         string `json:"code" validate:"required,min=1"`
	CodeVerifier string `json:"code_verifier" validate:"required,min=1"`
}
