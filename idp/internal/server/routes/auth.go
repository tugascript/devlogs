package routes

import (
	"github.com/gofiber/fiber/v2"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func (r *Routes) AuthRoutes(app *fiber.App) {
	router := v1PathRouter(app).Group(paths.AuthBase)

	// Custom auth paths
	router.Post(paths.AuthRegister, r.controllers.RegisterAccount)
	router.Post(paths.AuthConfirmEmail, r.controllers.ConfirmAccount)
	router.Post(paths.AuthLogin, r.controllers.LoginAccount)
	router.Post(paths.AuthLogin2FA, r.controllers.TwoFAAccessClaimsMiddleware, r.controllers.TwoFactorLoginAccount)
	router.Post(paths.AuthRefresh, r.controllers.RefreshAccount)
	router.Post(paths.AuthLogout, r.controllers.AccountAccessClaimsMiddleware, r.controllers.LogoutAccount)

	// Known auth paths (oauth2)
	router.Post(paths.AuthOAuthKeys, r.controllers.AccountOAuthPublicJWKs)
	router.Post(paths.AuthOAuthToken, r.controllers.AccountOAuthToken)

	// OAuth2 log ins
	router.Post(paths.AuthOAuthAppleCallback, r.controllers.AccountAppleCallback)
	router.Get(paths.AuthOAuthURL, r.controllers.AccountOAuthURL)
	router.Get(paths.AuthOAuthCallback, r.controllers.AccountOAuthCallback)
}
