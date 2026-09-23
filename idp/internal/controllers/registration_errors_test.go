package controllers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

func TestRegistrationErrorResponses(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := &Controllers{logger: logger}
	for _, tc := range []struct {
		name            string
		handler         fiber.Handler
		status          int
		challenge, code string
	}{
		{"forbidden management", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewError(exceptions.CodeForbidden, "denied"))
		}, http.StatusForbidden, "", exceptions.OAuthErrorAccessDenied},
		{"infrastructure failure", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewInternalServerError())
		}, http.StatusInternalServerError, "", exceptions.OAuthErrorServerError},
		{"invalid secret metadata", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewError(exceptions.OAuthErrorInvalidClientMetadata, "invalid secret"))
		}, http.StatusBadRequest, "", exceptions.OAuthErrorInvalidClientMetadata},
		{"missing IAT", c.DynamicRegistrationIATMiddleware, http.StatusUnauthorized, "Bearer", ""},
		{"invalid IAT", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewError(exceptions.OAuthErrorInvalidToken, "invalid IAT"))
		}, http.StatusUnauthorized, `Bearer error="invalid_token"`, exceptions.OAuthErrorInvalidToken},
		{"missing statement issuer", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewInvalidTokenError("issuer required"))
		}, http.StatusBadRequest, "", exceptions.OAuthErrorInvalidSoftwareStatement},
		{"unapproved statement", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewUnauthorizedTokenError("unapproved issuer"))
		}, http.StatusBadRequest, "", exceptions.OAuthErrorUnapprovedSoftwareStatement},
		{"invalid request metadata", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewError(exceptions.OAuthErrorInvalidRequest, "invalid request"))
		}, http.StatusBadRequest, "", exceptions.OAuthErrorInvalidRequest},
		{"invalid client authentication", func(ctx fiber.Ctx) error {
			return dynamicRegistrationServiceError(logger, ctx, exceptions.NewError(exceptions.OAuthErrorInvalidClient, "invalid client"))
		}, http.StatusUnauthorized, "", exceptions.OAuthErrorInvalidClient},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := fiber.New()
			app.Post("/register", tc.handler)
			res, err := app.Test(httptest.NewRequest(http.MethodPost, "/register", nil))
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != tc.status || res.Header.Get("WWW-Authenticate") != tc.challenge {
				t.Fatalf("status=%d (want %d) challenge=%q (want %q)", res.StatusCode, tc.status, res.Header.Get("WWW-Authenticate"), tc.challenge)
			}
			body, err := io.ReadAll(res.Body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.code == "" {
				if len(body) != 0 {
					t.Fatalf("missing credentials must not return an error code: %s", body)
				}
				return
			}
			var payload struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				t.Fatal(err)
			}
			if payload.Error != tc.code {
				t.Fatalf("error=%q, want %q", payload.Error, tc.code)
			}
		})
	}
}
