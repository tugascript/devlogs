package services

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func TestRegistrationMetadataDefaultsAndValidation(t *testing.T) {
	cases := []struct {
		name      string
		data      ApplicationRegistrationData
		errorCode string
	}{
		{name: "defaults", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback/"}}},
		{name: "missing redirect", errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "fragment", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/#fragment"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "empty fragment", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/#"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "relative redirect", data: ApplicationRegistrationData{RedirectURIs: []string{"/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "client credentials without responses", data: ApplicationRegistrationData{GrantTypes: []string{"client_credentials"}, ResponseTypes: []string{}}},
		{name: "inconsistent grant and response", data: ApplicationRegistrationData{GrantTypes: []string{"client_credentials"}}, errorCode: exceptions.CodeValidation},
		{name: "authorization code without code response", data: ApplicationRegistrationData{GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{}}, errorCode: exceptions.CodeValidation},
		{name: "both key sources", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/cb"}, JWKs: &utils.JWKSet{}, JWKsURI: "https://example.com/jwks"}, errorCode: exceptions.CodeValidation},
		{name: "native custom scheme", data: ApplicationRegistrationData{RedirectURIs: []string{"com.example.app:/callback"}}},
		{name: "remote HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "uppercase remote HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"HTTP://example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "localhost lookalike", data: ApplicationRegistrationData{RedirectURIs: []string{"http://localhost.example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "private LAN HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://192.168.1.1/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "localhost HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://localhost:8080/callback"}}},
		{name: "IPv4 loopback HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://127.0.0.1:8080/callback"}}},
		{name: "IPv6 loopback HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://[::1]:8080/callback"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.data.RedirectURIs...)
			err := normalizeRegistrationMetadata(&tc.data)
			if tc.errorCode != "" {
				if err == nil || err.Code != tc.errorCode {
					t.Fatalf("error=%v, want %s", err, tc.errorCode)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(before, tc.data.RedirectURIs) {
				t.Fatal("redirect URI changed")
			}
			if tc.data.TokenEndpointAuthMethod != "client_secret_basic" {
				t.Fatal("incorrect authentication default")
			}
			mapped, mapErr := mapRegistrationResponseTypes(tc.data.ResponseTypes)
			if mapErr != nil || len(mapped) != len(tc.data.ResponseTypes) {
				t.Fatalf("response types changed: %v %v", mapped, mapErr)
			}
		})
	}
}

func TestSoftwareStatementIssuerClassification(t *testing.T) {
	s := &Services{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, tc := range []struct{ name, issuer, want string }{
		{"missing", "", exceptions.CodeInvalidToken},
		{"unapproved", "https://other.example.net", exceptions.CodeUnauthorizedToken},
		{"approved", "https://client.example.com", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.verifySoftwareStatementSTDClaims(context.Background(), verifySoftwareStatementSTDClaimsOptions{
				domain: "client.example.com", baseDomain: "example.com", claims: &jwt.RegisteredClaims{Issuer: tc.issuer},
			})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || err.Code != tc.want {
				t.Fatalf("error=%v, want %s", err, tc.want)
			}
		})
	}
}

func TestRegistrationRequiresVerifiedIATDomain(t *testing.T) {
	s := &Services{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := s.CreateAccountCredentialsRegistration(context.Background(), CreateAccountCredentialsRegistrationOptions{ClientURI: "https://client.example.com"})
	if err == nil || err.Code != exceptions.OAuthErrorInvalidToken {
		t.Fatalf("account error=%v", err)
	}
	_, err = s.CreateAppCredentialsRegistration(context.Background(), CreateAppCredentialsRegistrationOptions{IsAuthenticated: true, ClientURI: "https://client.example.com"})
	if err == nil || err.Code != exceptions.OAuthErrorInvalidToken {
		t.Fatalf("app error=%v", err)
	}
}

func TestRegistrationRejectsOtherIATDomains(t *testing.T) {
	s := &Services{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	for _, domain := range []string{"sibling.example.com", "other.example.net", "client.example.com.attacker.net"} {
		t.Run(domain, func(t *testing.T) {
			// Reject before looking up domain approval in the database, even when
			// both domains might otherwise be approved for this account.
			_, err := s.checkClientRegistrationDomain(context.Background(), checkClientRegistrationDomainOptions{
				iatDomain: "client.example.com", domain: domain,
			})
			if err == nil || err.Code != exceptions.CodeUnauthorized {
				t.Fatalf("error=%v, want unauthorized", err)
			}
		})
	}
}

func TestSoftwareStatementMergeUsesPresence(t *testing.T) {
	body := ApplicationRegistrationData{ClientName: "body", ClientURI: "https://example.com", RequireAuthTime: true, DefaultMaxAge: 60, ResponseTypes: []string{}, Contacts: []string{"old@example.com"}}
	statement := tokens.SoftwareStatementClaims{RawMetadata: map[string]json.RawMessage{
		"client_name": json.RawMessage(`"signed"`), "require_auth_time": json.RawMessage(`false`), "default_max_age": json.RawMessage(`0`), "contacts": json.RawMessage(`[]`), "unknown_extension": json.RawMessage(`{"ignored":true}`),
	}}
	merged, err := mergeRegistrationMetadata(body, statement)
	if err != nil {
		t.Fatal(err)
	}
	if merged.ClientName != "signed" || merged.RequireAuthTime || merged.DefaultMaxAge != 0 || len(merged.Contacts) != 0 {
		t.Fatalf("statement did not override body: %+v", merged)
	}
	if merged.ClientURI != body.ClientURI || merged.ResponseTypes == nil {
		t.Fatal("omitted statement fields did not preserve body metadata")
	}
}
