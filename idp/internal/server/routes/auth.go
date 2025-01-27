package routes

import "github.com/gofiber/fiber/v2"

const (
	AuthPath string = "/auth"

	AuthRegisterPath     string = "/register"
	AuthConfirmEmailPath string = "/confirm-email"
	AuthLoginPath        string = "/login"
	AuthLogin2FAPath     string = "/login/2fa"
	AuthRefreshPath      string = "/refresh"
	AuthLogoutPath       string = "/logout"

	AuthOAuthPathKeys  string = "/oauth2/jwks"
	AuthOAuthTokenPath string = "/oauth2/token"

	AuthOAuthAppleCallbackPath string = "/oauth2/apple/callback"
	AuthOAuthURLPath           string = "/oauth2/:provider"
	AuthOAuthCallbackPath      string = "/oauth2/:provider/callback"
)

func (r *Routes) AuthRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(AuthPath)

	// Custom auth paths
	router.Post(AuthRegisterPath, r.controllers.RegisterAccount)
	router.Post(AuthConfirmEmailPath, r.controllers.ConfirmAccount)
	router.Post(AuthLoginPath, r.controllers.LoginAccount)
	router.Post(AuthLogin2FAPath, r.controllers.TwoFAAccessClaimsMiddleware, r.controllers.TwoFactorLoginAccount)
	router.Post(AuthRefreshPath, r.controllers.RefreshAccount)
	router.Post(AuthLogoutPath, r.controllers.AccountAccessClaimsMiddleware, r.controllers.LogoutAccount)

	// Known auth paths (oauth2)
	router.Post(AuthOAuthPathKeys, r.controllers.AccountOAuthPublicJWKs)
	router.Post(AuthOAuthTokenPath, r.controllers.AccountOAuthToken)

	// OAuth2 log ins
	router.Post(AuthOAuthAppleCallbackPath, r.controllers.AccountAppleCallback)
	router.Post(AuthOAuthURLPath, r.controllers.AccountOAuthURL)
	router.Post(AuthOAuthCallbackPath, r.controllers.AccountOAuthCallback)
}
