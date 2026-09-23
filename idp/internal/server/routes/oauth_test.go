package routes

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v3"
	"github.com/tugascript/devlogs/idp/internal/controllers"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
)

func TestOAuthIATRoutesRejectUnknownHosts(t *testing.T) {
	ctrl := controllers.NewControllers(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, validator.New(), "example.com", "id.example.com", "session")
	app := fiber.New()
	NewRoutes(ctrl).OAuthRoutes(app)
	base := paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken
	client := "/abcdefghijklmnopqrstuv"
	for _, tc := range []struct{ method, path string }{
		{"GET", paths.OAuthAuth}, {"POST", paths.OAuthToken},
		{"GET", client + paths.AuthLogin}, {"POST", client + paths.AuthLogin},
		{"GET", client + paths.AuthLogin + paths.Auth2FA}, {"POST", client + paths.AuthLogin + paths.Auth2FA},
		{"GET", client + paths.InitialAccessTokenAuthEXT + "/google"},
		{"GET", client + paths.InitialAccessTokenAuthEXT + "/google" + paths.InitialAccessTokenCallback},
		{"POST", client + paths.InitialAccessTokenAuthEXT + "/apple" + paths.InitialAccessTokenCallback},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			response, err := app.Test(httptest.NewRequest(tc.method, "https://untrusted.example"+base+tc.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != 404 {
				t.Fatalf("unknown host: got %d", response.StatusCode)
			}
			// The same route on the base host reaches request validation.
			response, err = app.Test(httptest.NewRequest(tc.method, "https://id.example.com"+base+tc.path, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode < 400 || response.StatusCode == 404 || response.StatusCode >= 500 {
				t.Fatalf("base-host route not reached: got %d", response.StatusCode)
			}
		})
	}
}

func TestRegistrationUnsupportedMethods(t *testing.T) {
	ctrl := controllers.NewControllers(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, validator.New(), "example.com", "id.example.com", "session")
	app := fiber.New()
	NewRoutes(ctrl).OAuthRoutes(app)
	for _, method := range []string{"POST", "PATCH"} {
		res, err := app.Test(httptest.NewRequest(method, "https://id.example.com"+paths.V1+paths.AuthBase+paths.OAuthBase+paths.OAuthRegister+"/client", nil))
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 405 || res.Header.Get("Allow") != "GET, PUT, DELETE" {
			t.Fatalf("%s: status=%d allow=%q", method, res.StatusCode, res.Header.Get("Allow"))
		}
	}
}
