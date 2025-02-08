package bodies

type AccountCredentialsBody struct {
	Scopes []string `json:"scopes" validate:"required,unique,oneof=admin users:read users:write apps:read apps:write"`
}
