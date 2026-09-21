package controllers

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/tugascript/devlogs/idp/internal/controllers/bodies"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/services/templates"
)

func TestAppsIATControllersRequireHostContext(t *testing.T) {
	c := NewControllers(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, validator.New(), "example.com", "id.example.com", "session")
	for name, handler := range map[string]fiber.Handler{
		"auth":      c.AppsOAuthDynamicRegistrationIATAuth,
		"loginGet":  c.AppsOAuthDynamicRegistrationIATLoginGet,
		"loginPost": c.AppsOAuthDynamicRegistrationIATLoginPost,
		"twoFAGet":  c.AppsOAuthDynamicRegistrationIAT2FAGet,
		"twoFAPost": c.AppsOAuthDynamicRegistrationIAT2FAPost,
		"external":  c.AppsOAuthDynamicRegistrationIATExtAuthGet,
		"callback":  c.AppsOAuthDynamicRegistrationIATExtCB,
		"apple":     c.AppsOAuthDynamicRegistrationIATExtAppleCB,
		"token":     c.AppsOAuthDynamicRegistrationIATToken,
	} {
		t.Run(name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/", handler)
			response, err := app.Test(httptest.NewRequest("GET", "https://id.example.com/", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode < 400 || response.StatusCode >= 500 {
				t.Fatalf("expected client error without tenant context, got %d", response.StatusCode)
			}
		})
	}
}

func TestAppsIATTemplatesUseRegisteredRoutes(t *testing.T) {
	const clientID = "abcdefghijklmnopqrstuv"
	base := oauthDynamicRegistrationIATCookiePath() + "/" + clientID
	login, err := templates.BuildAccountDynamicRegistrationIATAuthTemplate(templates.AccountDynamicRegistrationIATAuthOptions{ACCClientID: clientID, AppleEnabled: true, GoogleEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	login = strings.ReplaceAll(login, `\/`, `/`)
	for _, path := range []string{base + paths.AuthLogin, base + paths.InitialAccessTokenAuthEXT + "/apple", base + paths.InitialAccessTokenAuthEXT + "/google"} {
		if !strings.Contains(login, path) {
			t.Errorf("login template missing route %s", path)
		}
	}
	twoFA, err := templates.BuildAccountDynamicRegistrationIAT2FATemplate(templates.AccountDynamicRegistrationIAT2FAOptions{ACCClientID: clientID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(twoFA, base+paths.AuthLogin+paths.Auth2FA) {
		t.Fatal("2FA form points to an unregistered route")
	}
}

func TestAppsIATResumePreservesAuthorization(t *testing.T) {
	fields := bodies.OAuthDynamicRegistrationIATAuthHiddenFieldsBody{
		ClientID: "client.example", ResponseType: "code", State: "state & value",
		RedirectURI: "https://client.example/callback?value=1", CodeChallenge: "challenge", CodeChallengeMethod: "S256", CSRFToken: "secret",
	}
	resume, err := url.Parse(appsIATResumeURL(fields))
	if err != nil {
		t.Fatal(err)
	}
	if resume.IsAbs() {
		t.Fatal("resume must remain on the tenant host")
	}
	for key, want := range map[string]string{"client_id": fields.ClientID, "response_type": "code", "state": fields.State, "redirect_uri": fields.RedirectURI, "code_challenge": fields.CodeChallenge, "code_challenge_method": "S256"} {
		if got := resume.Query().Get(key); got != want {
			t.Errorf("%s: got %q want %q", key, got, want)
		}
	}
	if resume.Query().Has("csrf_token") {
		t.Fatal("CSRF token leaked into redirect")
	}
}

func TestAppsIATCookieRemovalIsHostOnly(t *testing.T) {
	c := &Controllers{cookieName: "session"}
	app := fiber.New()
	app.Get("/", func(ctx fiber.Ctx) error {
		c.removeAppIATCookie(ctx)
		c.removeAppIAT2FACookie(ctx)
		return ctx.SendStatus(204)
	})
	response, err := app.Test(httptest.NewRequest("GET", "https://tenant.example.com/", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if len(response.Cookies()) != 2 {
		t.Fatal("expected both apps cookies to be removed")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != oauthDynamicRegistrationIATCookiePath() || cookie.MaxAge >= 0 {
			t.Fatalf("invalid cookie scope: %+v", cookie)
		}
		if cookie.Name != "session_app_iat" && cookie.Name != "session_app_iat_2fa" {
			t.Fatalf("unexpected cookie: %s", cookie.Name)
		}
	}
}
