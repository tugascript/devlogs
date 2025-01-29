package paths

const (
	AuthBase string = "/auth"

	AuthRegister     string = "/register"
	AuthConfirmEmail string = "/confirm-email"
	AuthLogin        string = "/login"
	AuthLogin2FA     string = "/login/2fa"
	AuthRefresh      string = "/refresh"
	AuthLogout       string = "/logout"

	AuthOAuthKeys  string = "/oauth2/jwks"
	AuthOAuthToken string = "/oauth2/token"

	AuthOAuthAppleCallback string = "/oauth2/apple/callback"
	AuthOAuthURL           string = "/oauth2/:provider"
	AuthOAuthCallback      string = "/oauth2/:provider/callback"
)
