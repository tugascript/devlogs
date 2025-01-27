package dtos

type AuthDTO struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Message      string `json:"message,omitempty"`
}

const tokenType string = "Bearer"

func NewAuthDTO(accessToken string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken: accessToken,
		ExpiresIn:   int(expiresIn),
	}
}

func NewFullAuthDTO(accessToken, refreshToken string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(expiresIn),
		TokenType:    tokenType,
	}
}

func NewTempAuthDTO(accessToken, message string, expiresIn int64) AuthDTO {
	return AuthDTO{
		AccessToken:  accessToken,
		RefreshToken: "",
		ExpiresIn:    int(expiresIn),
		TokenType:    tokenType,
		Message:      message,
	}
}
