package controllers

import (
	"github.com/gofiber/fiber/v3"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationUpdateBody(t *testing.T) {
	for _, tc := range []struct {
		name, body, contentType string
		valid, present          bool
	}{
		{"omitted", `{"client_id":"client"}`, "application/json", true, false},
		{"present", `{"client_id":"client","client_secret":"secret"}`, "application/json", true, true},
		{"empty", `{"client_secret":""}`, "application/json", false, false},
		{"null secret", `{"client_secret":null}`, "application/json", false, false},
		{"null body", `null`, "application/json", false, false},
		{"array", `[]`, "application/json", false, false},
		{"form", `client_id=client`, "application/x-www-form-urlencoded", false, false},
		{"token", `{"registration_access_token":"x"}`, "application/json", false, false},
		{"uri", `{"registration_client_uri":null}`, "application/json", false, false},
		{"expiry", `{"client_secret_expires_at":0}`, "application/json", false, false},
		{"issued at", `{"client_id_issued_at":0}`, "application/json", false, false},
		{"extension", `{"custom_extension":true}`, "application/json", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			c := new(Controllers)
			app.Put("/register", func(ctx fiber.Ctx) error {
				body, err := c.bindRegistrationBody(ctx)
				if (err == nil) != tc.valid {
					t.Errorf("valid=%v error=%v", tc.valid, err)
				}
				if err == nil && body.ClientSecretPresent != tc.present {
					t.Errorf("secret presence=%v", body.ClientSecretPresent)
				}
				return ctx.SendStatus(204)
			})
			req := httptest.NewRequest("PUT", "/register", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			res, err := app.Test(req)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
		})
	}
}
