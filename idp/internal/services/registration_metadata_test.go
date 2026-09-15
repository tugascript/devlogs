package services

import (
	"encoding/json"
	"reflect"
	"testing"

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
