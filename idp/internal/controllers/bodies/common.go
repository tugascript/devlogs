package bodies

type RefreshTokenBody struct {
	RefreshToken string `json:"refresh_token" validate:"required,jwt"`
}

type ConfirmationTokenBody struct {
	ConfirmationToken string `json:"confirmation_token" validate:"required,jwt"`
}

type LoginBody struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=1"`
}

type TwoFactorLoginBody struct {
	Code string `json:"code" validate:"required,mix=6,max=6"`
}

type GrantRefreshTokenBody struct {
	GrantType    string `json:"grant_type" validate:"required,eq=refresh_token"`
	RefreshToken string `json:"refresh_token" validate:"required,jwt"`
}

type AuthCodeLoginBody struct {
	GrantType   string `json:"grant_type" validate:"required,eq=authorization_code"`
	Code        string `json:"code" validate:"required,min=1,max=30,alphanum"`
	State       string `json:"state" validate:"required,min=1,hexadecimal"`
	RedirectURI string `json:"redirect_uri" validate:"required,url"`
}

type ClientCredentialsBody struct {
	GrantType string `json:"grant_type" validate:"required,eq=client_credentials"`
	Audience  string `json:"audience,omitempty" validate:"url"`
}

type AppleLoginBody struct {
	Code  string `json:"code" validate:"required,min=1"`
	State string `json:"state" validate:"required,min=1"`
	User  string `json:"user" validate:"required,json"`
}

type AppleUserName struct {
	FirstName string `json:"firstName" validate:"required,min=1"`
	LastName  string `json:"lastName" validate:"required,min=1"`
}

type AppleUser struct {
	Name  AppleUserName `json:"name" validate:"required"`
	Email string        `json:"email" validate:"required,email"`
}
