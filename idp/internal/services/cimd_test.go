// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type cimdRoundTripper func(*http.Request) (*http.Response, error)

func (f cimdRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func cimdTestHTTPClient(status int, contentType, cacheControl, body string) *http.Client {
	return &http.Client{Transport: cimdRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Header: http.Header{
				"Content-Type":  []string{contentType},
				"Cache-Control": []string{cacheControl},
			},
			Body: io.NopCloser(strings.NewReader(body)),
		}, nil
	})}
}

func validCIMDJSON(clientID string) string {
	return `{"client_id":"` + clientID + `","client_name":"Example MCP Client","redirect_uris":["http://127.0.0.1:3000/callback"],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
}

func TestFetchCIMDClientMetadata(t *testing.T) {
	clientID := "https://client.example/oauth/client.json"
	got, err := fetchCIMDClientMetadata(context.Background(), clientID, cimdTestHTTPClient(
		http.StatusOK, "application/json", "public, max-age=120", validCIMDJSON(clientID),
	))
	if err != nil {
		t.Fatal(err)
	}
	if got.Metadata.ClientName != "Example MCP Client" || got.CacheTTL != 120*time.Second {
		t.Fatalf("unexpected fetch result: %#v", got)
	}
}

func TestFetchCIMDRejectsBadResponses(t *testing.T) {
	clientID := "https://client.example/oauth/client.json"
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
	}{
		{"redirect", http.StatusFound, "application/json", validCIMDJSON(clientID)},
		{"non-json content type", http.StatusOK, "text/plain", validCIMDJSON(clientID)},
		{"malformed json", http.StatusOK, "application/json", "{"},
		{"oversized", http.StatusOK, "application/json", strings.Repeat("x", cimdMaxDocumentBytes+1)},
		{"trailing json", http.StatusOK, "application/json", validCIMDJSON(clientID) + `{}`},
		{"id mismatch", http.StatusOK, "application/json", strings.Replace(validCIMDJSON(clientID), clientID, "https://other.example/client.json", 1)},
		{"missing redirect", http.StatusOK, "application/json", `{"client_id":"` + clientID + `","client_name":"Client","grant_types":["authorization_code"],"token_endpoint_auth_method":"none"}`},
		{"bad redirect", http.StatusOK, "application/json", strings.Replace(validCIMDJSON(clientID), "http://127.0.0.1:3000/callback", "/relative", 1)},
		{"secret auth method", http.StatusOK, "application/json", strings.Replace(validCIMDJSON(clientID), `"none"`, `"client_secret_basic"`, 1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := fetchCIMDClientMetadata(context.Background(), clientID, cimdTestHTTPClient(tt.status, tt.contentType, "", tt.body))
			if err == nil || !errors.Is(err, errInvalidCIMD) {
				t.Fatalf("expected invalid CIMD error, got %v", err)
			}
		})
	}
}

func TestParseCIMDURLRequiresHTTPSAndPath(t *testing.T) {
	for _, clientID := range []string{
		"http://client.example/client.json",
		"https://client.example",
		"https://user@client.example/client.json",
		"https://client.example/client.json#fragment",
	} {
		if _, err := parseCIMDURL(clientID); err == nil {
			t.Errorf("expected %q to be rejected", clientID)
		}
	}
}

func TestValidateCIMDAllowsNativeRedirectURI(t *testing.T) {
	clientID := "https://client.example/oauth/client.json"
	metadata := CIMDClientMetadata{
		ClientID: clientID, ClientName: "Native client", RedirectURIs: []string{"com.example.app:/oauth/callback"},
		GrantTypes: []string{"authorization_code"}, TokenEndpointAuthMethod: "none",
	}
	if err := validateCIMDMetadata(clientID, metadata); err != nil {
		t.Fatalf("custom-scheme redirect URI should be accepted: %v", err)
	}
}

func TestCIMDCacheTTL(t *testing.T) {
	tests := []struct {
		control string
		want    time.Duration
	}{
		{"public, max-age=20", 20 * time.Second},
		{"max-age=999999", cimdMaxCacheTTL},
		{"no-store", 0},
		{"no-cache", 0},
		{"", cimdDefaultCacheTTL},
	}
	for _, tt := range tests {
		if got := cimdCacheTTL(http.Header{"Cache-Control": []string{tt.control}}); got != tt.want {
			t.Errorf("cimdCacheTTL(%q) = %s, want %s", tt.control, got, tt.want)
		}
	}
}

func TestIsPublicCIMDAddress(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"8.8.8.8", true},
		{"10.0.0.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"192.31.196.1", false},
		{"127.0.0.1", false},
		{"2001:4860:4860::8888", true},
		{"2001:db8::1", false},
		{"::1", false},
	}
	for _, tt := range tests {
		ip, err := netip.ParseAddr(tt.ip)
		if err != nil {
			t.Fatal(err)
		}
		if got := isPublicCIMDAddress(ip); got != tt.want {
			t.Errorf("isPublicCIMDAddress(%s) = %t, want %t", tt.ip, got, tt.want)
		}
	}
}

func TestCIMDSafeDialRejectsPrivateAddressBeforeConnecting(t *testing.T) {
	if _, err := cimdSafeDialContext(context.Background(), "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("expected loopback address to be rejected before dialing")
	}
}

func TestValidateCIMDMetadataPrivateJWKS(t *testing.T) {
	clientID := "https://client.example/oauth/client.json"
	metadata := CIMDClientMetadata{
		ClientID: clientID, ClientName: "Confidential client", TokenEndpointAuthMethod: "private_key_jwt",
		JWKS: []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"private"}]}`),
	}
	if err := validateCIMDMetadata(clientID, metadata); err == nil {
		t.Fatal("expected private key material to be rejected")
	}
}
