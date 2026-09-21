package services

import (
	"context"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

func TestAppsRegistrationRequiresTenantContext(t *testing.T) {
	// All entry points must fail before touching a database, cache, or provider
	// when host middleware has not supplied a complete tenant context.
	s := reflect.ValueOf(&Services{})
	for i := 0; i < s.NumMethod(); i++ {
		name := s.Type().Method(i).Name
		if !strings.Contains(name, "AppsOAuthDynamicRegistration") {
			continue
		}
		method := s.Method(i)
		for _, missing := range []string{"Hostname", "AccountID"} {
			t.Run(name+"/missing"+missing, func(t *testing.T) {
				opts := reflect.New(method.Type().In(1)).Elem()
				if missing != "Hostname" {
					opts.FieldByName("Hostname").SetString("tenant.example.com")
				}
				if missing != "AccountID" {
					opts.FieldByName("AccountID").SetInt(42)
				}
				result := method.Call([]reflect.Value{reflect.ValueOf(context.Background()), opts})
				serviceErr, ok := result[len(result)-1].Interface().(*exceptions.ServiceError)
				if !ok || serviceErr == nil || serviceErr.Code != exceptions.CodeUnauthorized {
					t.Fatalf("expected unauthorized, got %v", serviceErr)
				}
			})
		}
	}
}

func TestDynamicRegistrationRequestBinding(t *testing.T) {
	saved := dynamicRegistrationRequest{domain: "client.example", state: "state", redirectURI: "https://client.example/callback"}
	for _, tc := range []struct {
		name    string
		request dynamicRegistrationRequest
		valid   bool
	}{
		{"match", saved, true},
		{"domain", dynamicRegistrationRequest{domain: "other.example", state: saved.state, redirectURI: saved.redirectURI}, false},
		{"state", dynamicRegistrationRequest{domain: saved.domain, state: "other", redirectURI: saved.redirectURI}, false},
		{"redirect", dynamicRegistrationRequest{domain: saved.domain, state: saved.state, redirectURI: "https://other.example/callback"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateDynamicRegistrationRequest(saved, tc.request)
			if (err == nil) != tc.valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
		})
	}
}

func TestDynamicRegistrationURLs(t *testing.T) {
	login, err := url.Parse(buildOAuthDynamicRegistrationIATLoginURL(buildOAuthDynamicRegistrationIATLoginURLOptions{
		accClientID: "client", domain: "client.example", state: "state & value", challenge: "challenge", challengeMethod: "S256", redirectURI: "https://client.example/callback",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if login.Query().Get("state") != "state & value" || login.Query().Get("code_challenge_method") != "S256" || !strings.Contains(login.Path, "/client/") {
		t.Fatalf("invalid login URL: %s", login)
	}
	callback, err := url.Parse(buildOAuthDynamicRegistrationIATCallbackURL(buildOAuthDynamicRegistrationIATCallbackURLOptions{
		redirectURI: "https://client.example/callback", code: "code", state: "state & value", issuerDomain: "tenant.example.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("iss") != "https://tenant.example.com" || callback.Query().Get("state") != "state & value" {
		t.Fatalf("invalid callback URL: %s", callback)
	}
}
