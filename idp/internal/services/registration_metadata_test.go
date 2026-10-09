package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"reflect"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func TestValidateSectorIdentifierHostRejectsPrivateTargets(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want bool
	}{
		{name: "public host", host: "example.com", want: false},
		{name: "localhost", host: "localhost", want: true},
		{name: "private ipv4", host: "10.0.0.5", want: true},
		{name: "link local ipv4", host: "169.254.169.254", want: true},
		{name: "loopback ipv6", host: "::1", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.host == "example.com" {
				orig := lookupSectorIdentifierIPs
				lookupSectorIdentifierIPs = func(ctx context.Context, host string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
				}
				defer func() { lookupSectorIdentifierIPs = orig }()
			}
			ips, err := validateSectorIdentifierHost(context.Background(), tc.host)
			if tc.want && err == nil {
				t.Fatal("expected blocked host error")
			}
			if !tc.want && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.want && len(ips) == 0 {
				t.Fatal("expected validated addresses")
			}
		})
	}
}

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
		{name: "client credentials without redirect or response metadata", data: ApplicationRegistrationData{ApplicationType: "web", GrantTypes: []string{"client_credentials"}}},
		{name: "client credentials without responses", data: ApplicationRegistrationData{GrantTypes: []string{"client_credentials"}, ResponseTypes: []string{}, RedirectURIs: []string{"https://example.com/callback"}}},
		{name: "inconsistent grant and response", data: ApplicationRegistrationData{GrantTypes: []string{"client_credentials"}, ResponseTypes: []string{"code"}, RedirectURIs: []string{"https://example.com/callback"}}, errorCode: exceptions.CodeValidation},
		{name: "authorization code without code response", data: ApplicationRegistrationData{GrantTypes: []string{"authorization_code"}, ResponseTypes: []string{}, RedirectURIs: []string{"https://example.com/callback"}}, errorCode: exceptions.CodeValidation},
		{name: "both key sources", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/cb"}, JWKs: &utils.JWKSet{}, JWKsURI: "https://example.com/jwks"}, errorCode: exceptions.CodeValidation},
		{name: "native custom scheme", data: ApplicationRegistrationData{ApplicationType: "native", RedirectURIs: []string{"com.example.app:/callback"}}},
		{name: "native remote HTTPS", data: ApplicationRegistrationData{ApplicationType: "native", RedirectURIs: []string{"https://example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "web custom scheme", data: ApplicationRegistrationData{ApplicationType: "web", RedirectURIs: []string{"com.example.app:/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "remote HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "uppercase remote HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"HTTP://example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "localhost lookalike", data: ApplicationRegistrationData{RedirectURIs: []string{"http://localhost.example.com/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "private LAN HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://192.168.1.1/callback"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "localhost HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://localhost:8080/callback"}}},
		{name: "IPv4 loopback HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://127.0.0.1:8080/callback"}}},
		{name: "IPv6 loopback HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"http://[::1]:8080/callback"}}},
		{name: "hybrid code id_token requires implicit", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, ResponseTypes: []string{"code id_token"}, GrantTypes: []string{"authorization_code"}}, errorCode: exceptions.CodeValidation},
		{name: "implicit grant requires id_token response", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, ResponseTypes: []string{"code"}, GrantTypes: []string{"authorization_code", "implicit"}}, errorCode: exceptions.CodeValidation},
		{name: "hybrid code id_token valid", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, ResponseTypes: []string{"code id_token"}, GrantTypes: []string{"authorization_code", "implicit"}}},
		{name: "implicit-only id_token valid", data: ApplicationRegistrationData{ApplicationType: "web", RedirectURIs: []string{"https://example.com/callback"}, ResponseTypes: []string{"id_token"}, GrantTypes: []string{"implicit"}}},
		{name: "web implicit localhost HTTP", data: ApplicationRegistrationData{ApplicationType: "web", RedirectURIs: []string{"http://localhost:8080/callback"}, ResponseTypes: []string{"code id_token"}, GrantTypes: []string{"authorization_code", "implicit"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "web implicit localhost HTTPS", data: ApplicationRegistrationData{ApplicationType: "web", RedirectURIs: []string{"https://localhost:8080/callback"}, ResponseTypes: []string{"code id_token"}, GrantTypes: []string{"authorization_code", "implicit"}}, errorCode: exceptions.OAuthErrorInvalidRedirectURI},
		{name: "web implicit remote HTTPS", data: ApplicationRegistrationData{ApplicationType: "web", RedirectURIs: []string{"https://example.com/callback"}, ResponseTypes: []string{"code id_token"}, GrantTypes: []string{"authorization_code", "implicit"}}},
		{name: "initiate login HTTP", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, InitiateLoginURI: "http://example.com/login"}, errorCode: exceptions.CodeValidation},
		{name: "initiate login HTTPS", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, InitiateLoginURI: "https://example.com/login"}},
		{name: "request uri HTTP without keys", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, RequestURIs: []string{"http://example.com/request.jwt"}}, errorCode: exceptions.CodeValidation},
		{name: "request uri HTTPS", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, RequestURIs: []string{"https://example.com/request.jwt"}}},
		{name: "request uri HTTP with keys and alg", data: ApplicationRegistrationData{RedirectURIs: []string{"https://example.com/callback"}, RequestURIs: []string{"http://example.com/request.jwt"}, JWKsURI: "https://example.com/jwks", RequestObjectSigningAlg: "ES256"}},
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

func TestMapResponseTypesWithDefaultIncludesStandaloneIDToken(t *testing.T) {
	responseTypes, err := mapResponseTypesWithDefault([]string{"id_token"})
	if err != nil {
		t.Fatalf("map id_token response type: %v", err)
	}
	if len(responseTypes) != 1 || responseTypes[0] != database.ResponseTypeIDToken {
		t.Fatalf("mapped response types = %v, want [%s]", responseTypes, database.ResponseTypeIDToken)
	}
}

func TestServiceRegistrationMetadataDoesNotNeedRedirectOrResponseTypes(t *testing.T) {
	data := ApplicationRegistrationData{
		ApplicationType:         "web",
		ClientURI:               "https://example.com",
		TokenEndpointAuthMethod: "private_key_jwt",
		GrantTypes:              []string{"client_credentials", "urn:ietf:params:oauth:grant-type:jwt-bearer"},
	}

	if err := normalizeRegistrationMetadata(&data); err != nil {
		t.Fatal(err)
	}
	if len(data.RedirectURIs) != 0 {
		t.Fatalf("redirect URIs = %v, want none", data.RedirectURIs)
	}
	if len(data.ResponseTypes) != 0 {
		t.Fatalf("response types = %v, want none", data.ResponseTypes)
	}
}

func TestAppTypesAndServiceGrants(t *testing.T) {
	for _, appType := range []string{"web", "native"} {
		if _, err := mapAppTypeToDB(appType); err != nil {
			t.Errorf("mapAppTypeToDB(%q): %v", appType, err)
		}
	}
	for _, appType := range []string{"spa", "backend", "device", "service", "mcp"} {
		if _, err := mapAppTypeToDB(appType); err == nil {
			t.Errorf("mapAppTypeToDB(%q) succeeded, want unsupported app type", appType)
		}
	}
	for _, credentialType := range []string{"service", "mcp"} {
		if _, err := mapAccountCredentialsType(credentialType); err != nil {
			t.Errorf("mapAccountCredentialsType(%q): %v", credentialType, err)
		}
	}

	serviceGrants := []database.GrantType{
		database.GrantTypeClientCredentials,
		database.GrantTypeUrnIetfParamsOauthGrantTypeJwtBearer,
	}
	if err := validateAppAuthGrantTypes(database.AppTypeWeb, database.AuthMethodPrivateKeyJwt, serviceGrants); err != nil {
		t.Fatalf("confidential web service grants: %v", err)
	}
	if err := validateAppAuthGrantTypes(database.AppTypeWeb, database.AuthMethodNone, serviceGrants); err == nil {
		t.Fatal("public web app accepted service grants")
	}
	if err := validateAppAuthGrantTypes(database.AppTypeNative, database.AuthMethodNone, serviceGrants); err == nil {
		t.Fatal("native app accepted service grants")
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
			if err == nil || err.Code != exceptions.OAuthErrorUnauthorizedClient {
				t.Fatalf("error=%v, want unauthorized_client", err)
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

func TestSectorIdentifierValidation(t *testing.T) {
	s := &Services{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	origFetch := fetchSectorIdentifierURIs
	origLookup := lookupSectorIdentifierIPs
	defer func() {
		fetchSectorIdentifierURIs = origFetch
		lookupSectorIdentifierIPs = origLookup
	}()

	fetchSectorIdentifierURIs = func(ctx context.Context, uri string, validatedIPs []net.IPAddr) ([]string, error) {
		if len(validatedIPs) != 1 || !validatedIPs[0].IP.Equal(net.ParseIP("93.184.216.34")) {
			t.Errorf("fetch received validated addresses %v, want [93.184.216.34]", validatedIPs)
		}
		if uri == "https://sector.example.com/redirects.json" {
			return []string{
				"https://client.example.com/callback",
				"https://client.example.com/callback2",
			}, nil
		}
		if uri == "https://sector.example.com/error.json" {
			return nil, errors.New("network failure")
		}
		return nil, errors.New("not found")
	}
	lookupSectorIdentifierIPs = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		if host == "localhost" {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		if host == "169.254.169.254" {
			return []net.IPAddr{{IP: net.ParseIP(host)}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
	}

	for _, tc := range []struct {
		name                string
		sectorIdentifierURI string
		redirectURIs        []string
		subjectType         string
		wantCode            string
	}{
		{
			name:                "empty sector URI with pairwise subject and single redirect",
			sectorIdentifierURI: "",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            "",
		},
		{
			name:                "empty sector URI with pairwise subject and same host redirects",
			sectorIdentifierURI: "",
			redirectURIs: []string{
				"https://client.example.com/callback",
				"https://client.example.com/callback2",
			},
			subjectType: "pairwise",
			wantCode:    "",
		},
		{
			name:                "empty sector URI with pairwise subject and different host redirects",
			sectorIdentifierURI: "",
			redirectURIs: []string{
				"https://client.example.com/callback",
				"https://other.example.net/callback",
			},
			subjectType: "pairwise",
			wantCode:    exceptions.OAuthErrorInvalidRedirectURI,
		},
		{
			name:                "non-HTTPS sector URI",
			sectorIdentifierURI: "http://sector.example.com/redirects.json",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            exceptions.OAuthErrorInvalidClientMetadata,
		},
		{
			name:                "sector URI with fragment",
			sectorIdentifierURI: "https://sector.example.com/redirects.json#fragment",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            exceptions.OAuthErrorInvalidClientMetadata,
		},
		{
			name:                "sector URI fetch error",
			sectorIdentifierURI: "https://sector.example.com/error.json",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            exceptions.OAuthErrorInvalidClientMetadata,
		},
		{
			name:                "sector URI localhost host",
			sectorIdentifierURI: "https://localhost/redirects.json",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            exceptions.OAuthErrorInvalidClientMetadata,
		},
		{
			name:                "sector URI private IP host",
			sectorIdentifierURI: "https://169.254.169.254/redirects.json",
			redirectURIs:        []string{"https://client.example.com/callback"},
			subjectType:         "pairwise",
			wantCode:            exceptions.OAuthErrorInvalidClientMetadata,
		},
		{
			name:                "sector URI missing redirect URI",
			sectorIdentifierURI: "https://sector.example.com/redirects.json",
			redirectURIs: []string{
				"https://client.example.com/callback",
				"https://not-in-sector.example.com/callback",
			},
			subjectType: "pairwise",
			wantCode:    exceptions.OAuthErrorInvalidRedirectURI,
		},
		{
			name:                "sector URI matching all redirect URIs",
			sectorIdentifierURI: "https://sector.example.com/redirects.json",
			redirectURIs: []string{
				"https://client.example.com/callback",
				"https://client.example.com/callback2",
			},
			subjectType: "pairwise",
			wantCode:    "",
		},
		{
			name:                "sector URI matching with public subject type",
			sectorIdentifierURI: "https://sector.example.com/redirects.json",
			redirectURIs: []string{
				"https://client.example.com/callback",
			},
			subjectType: "public",
			wantCode:    "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.validateSectorIdentifier(
				context.Background(),
				"req-1",
				tc.sectorIdentifierURI,
				tc.redirectURIs,
				tc.subjectType,
			)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else {
				if err == nil || err.Code != tc.wantCode {
					t.Fatalf("got err=%v, want code %s", err, tc.wantCode)
				}
			}
		})
	}
}

