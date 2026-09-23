package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/services"
	"github.com/tugascript/devlogs/idp/internal/services/dtos"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func oauthRegisterPath() string {
	return paths.V1 + paths.AuthBase + paths.OAuthBase + paths.OAuthRegister
}

func oauthRegisterClientPath(clientID string) string {
	return oauthRegisterPath() + "/" + clientID
}

func oauthIATTokenPath() string {
	return paths.V1 + paths.AuthBase + paths.OAuthBase + paths.InitialAccessToken + paths.OAuthToken
}

func requestURL(host, path string) string {
	return "https://" + host + path
}

func decodeJSONObject(t *testing.T, res *http.Response) map[string]json.RawMessage {
	t.Helper()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if len(bytes.TrimSpace(body)) == 0 {
		return response
	}
	if err = json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode json: %v body=%s", err, body)
	}
	return response
}

func jsonString(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func signSoftwareStatement(t *testing.T, private ed25519.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Unix()
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func generateEd25519JWK(t *testing.T) (ed25519.PrivateKey, string, utils.Ed25519JWK) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid := utils.Base62UUID()
	return private, kid, utils.EncodeEd25519Jwk(public, kid)
}

func approveSoftwareStatementKey(t *testing.T, account dtos.AccountDTO, publicJSON []byte, kid string, usage database.CredentialsUsage) {
	t.Helper()
	ctx := context.Background()
	db := GetTestDatabase(t)
	key, err := db.CreateCredentialsKey(ctx, database.CreateCredentialsKeyParams{
		AccountID: account.ID(), PublicKid: kid, PublicKey: publicJSON,
		CryptoSuite: database.TokenCryptoSuiteEdDSA, Usage: usage, ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var approvedID int32
	err = db.RawQueryRow(ctx, `INSERT INTO dynamic_registration_software_statement_keys (account_id,account_public_id,credentials_key_id,credentials_key_kid,root_domain) VALUES ($1,$2,$3,$4,$5) RETURNING id`, []interface{}{account.ID(), account.PublicID, key.ID, kid, "example.com"}).Scan(&approvedID)
	if err != nil {
		t.Fatal(err)
	}
}

type dcrSetup struct {
	account     dtos.AccountDTO
	domain      string
	host        string
	appClient   bool
	clientName  string
	body        map[string]any
	statement   string
	accessToken string
}

func cleanupAccount(t *testing.T, account dtos.AccountDTO) {
	t.Helper()
	t.Cleanup(func() {
		var id int32
		if err := GetTestDatabase(t).RawQueryRow(context.Background(), `DELETE FROM accounts WHERE id=$1 RETURNING id`, []interface{}{account.ID()}).Scan(&id); err != nil {
			t.Errorf("cleanup account: %v", err)
		}
	})
}

func setupDynamicRegistration(t *testing.T, appClient, bounded, statement bool) dcrSetup {
	t.Helper()
	ctx := context.Background()
	svc := GetTestServices(t)
	db := GetTestDatabase(t)
	cfg := GetTestConfig(t)
	account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
	cleanupAccount(t, account)

	domain := utils.Base62UUID() + ".example.com"
	domainRow, err := db.CreateDynamicRegistrationDomain(ctx, database.CreateDynamicRegistrationDomainParams{
		AccountID: account.ID(), AccountPublicID: account.PublicID, Domain: domain,
		VerificationMethod: database.DomainVerificationMethodDnsTxtRecord,
		Usages:             []database.DynamicRegistrationUsage{database.DynamicRegistrationUsageApp, database.DynamicRegistrationUsageAccount},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.VerifyDynamicRegistrationDomain(ctx, database.VerifyDynamicRegistrationDomainParams{
		ID: domainRow.ID, VerificationMethod: database.DomainVerificationMethodDnsTxtRecord,
	}); err != nil {
		t.Fatal(err)
	}

	var requireIAT, requireSS []string
	if bounded {
		requireIAT = []string{"web"}
	}
	if statement {
		requireSS = []string{"web"}
	}
	if appClient {
		if _, _, serviceErr := svc.SaveAppDynamicRegistrationConfig(ctx, services.SaveAppDynamicRegistrationConfigOptions{
			RequestID: uuid.NewString(), AccountPublicID: account.PublicID, AccountVersion: account.Version(),
			AllowedAppTypes: []string{"web"}, DefaultUsernameColumn: "email", DefaultAuthProviders: []string{"local"},
			DefaultAllowedScopes: []string{"openid", "profile"}, DefaultScopes: []string{"openid"},
			RequireInitialAccessTokenAppTypes: requireIAT, RequireSoftwareStatementAppTypes: requireSS,
			SoftwareStatementVerificationMethods: []string{"manual"}, InitialAccessTokenGenerationMethods: []string{"manual", "authorization_code"},
			InitialAccessTokenTtl: 300, InitialAccessTokenMaxUses: 10,
			AllowedGrantTypes: []string{"authorization_code", "refresh_token"}, AllowedResponseTypes: []string{"code"},
			AllowedTokenEndpointAuthMethods: []string{"client_secret_basic", "none", "private_key_jwt"}, MaxRedirectUris: 10,
		}); serviceErr != nil {
			t.Fatal(serviceErr)
		}
	} else {
		required := []string{}
		if statement {
			required = []string{"service"}
		}
		if _, _, serviceErr := svc.SaveAccountDynamicRegistrationConfig(ctx, services.SaveAccountDynamicRegistrationConfigOptions{
			RequestID: uuid.NewString(), AccountPublicID: account.PublicID, AccountVersion: account.Version(),
			AccountCredentialsTypes: []string{"service"}, RequireSoftwareStatementCredentialTypes: required,
			SoftwareStatementVerificationMethods: []string{"manual"},
		}); serviceErr != nil {
			t.Fatal(serviceErr)
		}
	}

	private, kid, jwk := generateEd25519JWK(t)
	publicJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	clientName := "Registration " + utils.Base62UUID()
	body := map[string]any{
		"client_name": clientName, "client_uri": "https://" + domain,
		"redirect_uris":              []string{"https://" + domain + "/callback/"},
		"token_endpoint_auth_method": "client_secret_basic", "grant_types": []string{"authorization_code"},
		"response_types": []string{"code"}, "scope": "profile", "contacts": []string{"developer@example.com"},
		"logo_uri": "https://" + domain + "/logo.png", "tos_uri": "https://" + domain + "/terms",
		"policy_uri": "https://" + domain + "/privacy", "software_id": uuid.NewString(), "software_version": "1.0",
		"jwks": map[string]any{"keys": []any{jwk}},
	}
	if appClient {
		body["application_type"] = "web"
		body["scope"] = "openid profile"
	} else {
		body["application_type"] = "service"
		body["grant_types"] = []string{"client_credentials"}
		body["response_types"] = []string{}
	}

	signedStatement := ""
	if statement {
		usage := database.CredentialsUsageApp
		if !appClient {
			usage = database.CredentialsUsageAccount
		}
		approveSoftwareStatementKey(t, account, publicJSON, kid, usage)
		signedStatement = signSoftwareStatement(t, private, kid, jwt.MapClaims{
			"iss": "https://" + domain, "iat": time.Now().Unix(),
			"client_name": clientName, "client_uri": "https://" + domain, "software_version": "2.0",
		})
		body["software_statement"] = signedStatement
		delete(body, "client_name")
		delete(body, "client_uri")
	}

	accessToken := ""
	if bounded {
		if appClient {
			auth, serviceErr := svc.CreateAppCredentialsRegistrationIAT(ctx, services.CreateAppCredentialsRegistrationIATOptions{
				RequestID: uuid.NewString(), AccountPublicID: account.PublicID, AccountVersion: account.Version(),
				Domain: domain, BackendDomain: cfg.BackendDomain(),
			})
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			accessToken = auth.AccessToken
		} else {
			signed, serviceErr := svc.CreateAccountCredentialsRegistrationIAT(ctx, services.CreateAccountCredentialsRegistrationIATOptions{
				RequestID: uuid.NewString(), AccountPublicID: account.PublicID, AccountVersion: account.Version(),
				Domain: domain, BackendDomain: cfg.BackendDomain(),
			})
			if serviceErr != nil {
				t.Fatal(serviceErr)
			}
			accessToken = signed
		}
	}

	host := cfg.BackendDomain()
	if appClient {
		host = account.Username + "." + host
	}
	return dcrSetup{
		account: account, domain: domain, host: host, appClient: appClient,
		clientName: clientName, body: body, statement: signedStatement, accessToken: accessToken,
	}
}

func assertCreatedRegistration(t *testing.T, setup dcrSetup, res *http.Response) (clientID, rat, registrationURI, secret string) {
	t.Helper()
	response := decodeJSONObject(t, res)
	clientID = jsonString(response["client_id"])
	returnedName := jsonString(response["client_name"])
	scope := jsonString(response["scope"])
	version := jsonString(response["software_version"])
	returnedStatement := jsonString(response["software_statement"])
	secret = jsonString(response["client_secret"])
	if parts := strings.Split(secret, "."); len(parts) != 2 || len(parts[0]) != 22 {
		t.Fatal("registration did not return a usable secretID.secretValue credential")
	}
	rat = jsonString(response["registration_access_token"])
	registrationURI = jsonString(response["registration_client_uri"])
	if clientID == "" || returnedName != setup.clientName || returnedStatement != setup.statement {
		t.Fatalf("unexpected response metadata: id=%q name=%q scope=%q", clientID, returnedName, scope)
	}
	if !strings.Contains(scope, "profile") {
		t.Fatalf("missing profile scope: %q", scope)
	}
	if setup.statement != "" && version != "2.0" {
		t.Fatal("statement did not override body software_version")
	}
	for _, field := range []string{"client_secret", "client_secret_expires_at", "client_id_issued_at", "grant_types", "response_types", "jwks", "contacts"} {
		if _, ok := response[field]; !ok {
			t.Errorf("missing %s", field)
		}
	}
	if rat == "" || registrationURI == "" {
		t.Fatal("missing registration_access_token or registration_client_uri")
	}
	if want := dtos.RegistrationClientURI(setup.host, clientID); registrationURI != want {
		t.Fatalf("registration_client_uri=%q want %q", registrationURI, want)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Error("registration response is cacheable")
	}

	ctx := context.Background()
	db := GetTestDatabase(t)
	if setup.appClient {
		row, err := db.FindAppByClientID(ctx, clientID)
		if err != nil {
			t.Fatal(err)
		}
		if row.AccountID != setup.account.ID() || row.ClientName != setup.clientName || len(row.Jwks) == 0 || row.RedirectUris[0] != "https://"+setup.domain+"/callback/" {
			t.Fatal("app metadata was not persisted correctly")
		}
		if row.CreationMethod != database.CreationMethodDynamicRegistration {
			t.Fatalf("creation_method=%q", row.CreationMethod)
		}
	} else {
		row, err := db.FindAccountCredentialsByClientID(ctx, clientID)
		if err != nil {
			t.Fatal(err)
		}
		if row.AccountID != setup.account.ID() || row.ClientName != setup.clientName || len(row.Jwks) == 0 || row.RedirectUris[0] != "https://"+setup.domain+"/callback/" {
			t.Fatal("account credentials metadata was not persisted correctly")
		}
		if row.CreationMethod != database.CreationMethodDynamicRegistration {
			t.Fatalf("creation_method=%q", row.CreationMethod)
		}
	}
	return clientID, rat, registrationURI, secret
}

// Exercise the actual HTTP route, IAT verification, software-statement trust,
// credential issuance and database persistence together.
func TestDynamicRegistration(t *testing.T) {
	testCases := make([]TestRequestCase[dcrSetup], 0, 6)
	for _, appClient := range []bool{true, false} {
		for _, bounded := range []bool{false, true} {
			if !appClient && !bounded {
				continue
			} // Account registration is protected by policy.
			for _, statement := range []bool{false, true} {
				appClient, bounded, statement := appClient, bounded, statement
				testCases = append(testCases, TestRequestCase[dcrSetup]{
					Name: fmt.Sprintf("app=%t/iat=%t/statement=%t", appClient, bounded, statement),
					ReqFn: func(t *testing.T) (dcrSetup, string) {
						setup := setupDynamicRegistration(t, appClient, bounded, statement)
						return setup, setup.accessToken
					},
					RequestBodyFn: func(setup dcrSetup) any { return setup.body },
					HostFn:        func(setup dcrSetup) string { return setup.host },
					ExpStatus:     http.StatusCreated,
					AssertFn: func(t *testing.T, setup dcrSetup, res *http.Response) {
						assertCreatedRegistration(t, setup, res)
					},
				})
			}
		}
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, oauthRegisterPath(), tc)
		})
	}
}

func TestDynamicRegistrationIATHostIsolation(t *testing.T) {
	cfg := GetTestConfig(t)

	assertInvalidToken := func(t *testing.T, _ dcrSetup, res *http.Response) {
		response := decodeJSONObject(t, res)
		AssertEqual(t, jsonString(response["error"]), exceptions.OAuthErrorInvalidToken)
		AssertEqual(t, res.Header.Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
	}
	testCases := []TestRequestCase[dcrSetup]{
		{
			Name: "account IAT cannot register an app",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				setup := setupDynamicRegistration(t, false, true, false)
				setup.host = setup.account.Username + "." + cfg.BackendDomain()
				setup.body["application_type"] = "web"
				if _, _, serviceErr := GetTestServices(t).SaveAppDynamicRegistrationConfig(context.Background(), services.SaveAppDynamicRegistrationConfigOptions{
					RequestID: uuid.NewString(), AccountPublicID: setup.account.PublicID, AccountVersion: setup.account.Version(),
					AllowedAppTypes: []string{"web"}, DefaultUsernameColumn: "email", DefaultAuthProviders: []string{"local"},
					DefaultAllowedScopes: []string{"openid", "profile"}, DefaultScopes: []string{"openid"},
					SoftwareStatementVerificationMethods: []string{"manual"}, InitialAccessTokenGenerationMethods: []string{"manual", "authorization_code"},
					InitialAccessTokenTtl: 300, InitialAccessTokenMaxUses: 10,
					AllowedGrantTypes: []string{"authorization_code", "refresh_token"}, AllowedResponseTypes: []string{"code"},
					AllowedTokenEndpointAuthMethods: []string{"client_secret_basic", "none", "private_key_jwt"}, MaxRedirectUris: 10,
				}); serviceErr != nil {
					t.Fatal(serviceErr)
				}
				return setup, setup.accessToken
			},
			RequestBodyFn: func(setup dcrSetup) any { return setup.body },
			HostFn:        func(setup dcrSetup) string { return setup.host },
			ExpStatus:     http.StatusUnauthorized,
			AssertFn:      assertInvalidToken,
		},
		{
			Name: "app IAT cannot register account credentials",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				setup := setupDynamicRegistration(t, true, true, false)
				setup.host = cfg.BackendDomain()
				setup.body["application_type"] = "native"
				return setup, setup.accessToken
			},
			RequestBodyFn: func(setup dcrSetup) any { return setup.body },
			HostFn:        func(setup dcrSetup) string { return setup.host },
			ExpStatus:     http.StatusUnauthorized,
			AssertFn:      assertInvalidToken,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodPost, oauthRegisterPath(), tc)
		})
	}
}

func TestDynamicRegistrationIATDomainBinding(t *testing.T) {
	for _, appClient := range []bool{false, true} {
		for _, statement := range []bool{false, true} {
			t.Run(fmt.Sprintf("app=%t/statement=%t", appClient, statement), func(t *testing.T) {
				PerformTestRequestCase(t, http.MethodPost, oauthRegisterPath(), TestRequestCase[dcrSetup]{
					ReqFn: func(t *testing.T) (dcrSetup, string) {
						setup := setupDynamicRegistration(t, appClient, true, statement)
						if statement {
							// The signed client_uri must override this conflicting unsigned value.
							setup.body["client_uri"] = "https://unsigned.example.net"
						} else {
							// Approve a second domain for this same account: the IAT must still
							// authorize only its own domain, not every approved domain.
							other := utils.Base62UUID() + ".example.com"
							_, err := GetTestDatabase(t).CreateDynamicRegistrationDomain(context.Background(), database.CreateDynamicRegistrationDomainParams{
								AccountID: setup.account.ID(), AccountPublicID: setup.account.PublicID, Domain: other,
								VerificationMethod: database.DomainVerificationMethodDnsTxtRecord,
								Usages:             []database.DynamicRegistrationUsage{database.DynamicRegistrationUsageApp, database.DynamicRegistrationUsageAccount},
							})
							if err != nil {
								t.Fatal(err)
							}
							setup.body["client_uri"] = "https://" + other
							setup.body["redirect_uris"] = []string{"https://" + other + "/callback/"}
						}
						return setup, setup.accessToken
					},
					RequestBodyFn: func(setup dcrSetup) any { return setup.body },
					HostFn:        func(setup dcrSetup) string { return setup.host },
					ExpStatus: func() int {
						if statement {
							return http.StatusCreated
						}
						return http.StatusUnauthorized
					}(),
					AssertFn: func(t *testing.T, setup dcrSetup, res *http.Response) {
						if statement {
							assertCreatedRegistration(t, setup, res)
							return
						}
						response := decodeJSONObject(t, res)
						AssertEqual(t, jsonString(response["error"]), exceptions.OAuthErrorUnauthorizedClient)
					},
				})
			})
		}
	}
}

func TestDynamicRegistrationSoftwareStatementFailures(t *testing.T) {
	setup := setupDynamicRegistration(t, true, false, false)
	goodPrivate, goodKid, goodJWK := generateEd25519JWK(t)
	goodJSON, err := json.Marshal(goodJWK)
	if err != nil {
		t.Fatal(err)
	}
	approveSoftwareStatementKey(t, setup.account, goodJSON, goodKid, database.CredentialsUsageApp)

	buildRequest := func(statement string) dcrSetup {
		request := setup
		request.body = cloneMap(setup.body)
		request.body["software_statement"] = statement
		return request
	}
	assertError := func(want string) func(*testing.T, dcrSetup, *http.Response) {
		return func(t *testing.T, _ dcrSetup, res *http.Response) {
			response := decodeJSONObject(t, res)
			AssertEqual(t, jsonString(response["error"]), want)
		}
	}

	testCases := []TestRequestCase[dcrSetup]{
		{
			Name: "bad signature",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				badPrivate, _, _ := generateEd25519JWK(t)
				return buildRequest(signSoftwareStatement(t, badPrivate, goodKid, jwt.MapClaims{
					"iss": "https://" + setup.domain, "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn:  assertError(exceptions.OAuthErrorInvalidSoftwareStatement),
		},
		{
			Name: "unapproved kid",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				private, kid, _ := generateEd25519JWK(t)
				return buildRequest(signSoftwareStatement(t, private, kid, jwt.MapClaims{
					"iss": "https://" + setup.domain, "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn:  assertError(exceptions.OAuthErrorUnapprovedSoftwareStatement),
		},
		{
			Name: "missing issuer",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				return buildRequest(signSoftwareStatement(t, goodPrivate, goodKid, jwt.MapClaims{
					"client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn:  assertError(exceptions.OAuthErrorInvalidSoftwareStatement),
		},
		{
			Name: "issuer mismatch",
			ReqFn: func(t *testing.T) (dcrSetup, string) {
				return buildRequest(signSoftwareStatement(t, goodPrivate, goodKid, jwt.MapClaims{
					"iss": "https://unrelated.example.net", "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})), ""
			},
			ExpStatus: http.StatusBadRequest,
			AssertFn:  assertError(exceptions.OAuthErrorUnapprovedSoftwareStatement),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tc.RequestBodyFn = func(setup dcrSetup) any { return setup.body }
			tc.HostFn = func(setup dcrSetup) string { return setup.host }
			PerformTestRequestCase(t, http.MethodPost, oauthRegisterPath(), tc)
		})
	}
}

func cloneMap(src map[string]any) map[string]any {
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func TestRFC7592ClientConfiguration(t *testing.T) {
	cfg := GetTestConfig(t)

	for _, clientType := range []struct {
		name      string
		appClient bool
		bounded   bool
	}{
		{name: "app", appClient: true},
		{name: "account credentials", bounded: true},
	} {
		clientType := clientType
		t.Run(clientType.name, func(t *testing.T) {
			var clientID, rat string
			createCase := TestRequestCase[dcrSetup]{
				Name: "register client",
				ReqFn: func(t *testing.T) (dcrSetup, string) {
					setup := setupDynamicRegistration(t, clientType.appClient, clientType.bounded, false)
					return setup, setup.accessToken
				},
				RequestBodyFn: func(setup dcrSetup) any { return setup.body },
				HostFn:        func(setup dcrSetup) string { return setup.host },
				ExpStatus:     http.StatusCreated,
				AssertFn: func(t *testing.T, setup dcrSetup, res *http.Response) {
					var registrationURI, secret string
					clientID, rat, registrationURI, secret = assertCreatedRegistration(t, setup, res)
					AssertEqual(t, registrationURI, requestURL(setup.host, oauthRegisterClientPath(clientID)))
					assertRFC7592Lifecycle(t, setup, clientID, rat, secret, cfg.BackendDomain())
				},
			}
			PerformTestRequestCase(t, http.MethodPost, oauthRegisterPath(), createCase)
		})
	}

	t.Run("well-known registration_endpoint", func(t *testing.T) {
		testCase := TestRequestCase[string]{
			ReqFn: func(t *testing.T) (string, string) {
				account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
				cleanupAccount(t, account)
				return account.Username + "." + cfg.BackendDomain(), ""
			},
			RequestBodyFn: func(string) any { return nil },
			HostFn:        func(host string) string { return host },
			ExpStatus:     http.StatusOK,
			AssertFn: func(t *testing.T, host string, res *http.Response) {
				response := decodeJSONObject(t, res)
				AssertEqual(t, jsonString(response["registration_endpoint"]), requestURL(host, oauthRegisterPath()))
			},
		}
		PerformTestRequestCase(t, http.MethodGet, paths.WellKnownBase+paths.WellKnownOIDC, testCase)
	})
}

type rfc7592Request struct {
	setup dcrSetup
	host  string
	path  string
	body  any
}

func assertRFC7592Lifecycle(t *testing.T, setup dcrSetup, clientID, rat, secret, backendDomain string) {
	t.Helper()
	updatedName := "Updated " + setup.clientName
	crossHost := backendDomain
	if !setup.appClient {
		crossHost = setup.account.Username + "." + backendDomain
	}
	clientPath := oauthRegisterClientPath(clientID)

	for _, tc := range []struct {
		name  string
		field string
		value any
	}{
		{"empty secret", "client_secret", ""}, {"null secret", "client_secret", nil}, {"wrong secret", "client_secret", "not-the-secret"},
		{"auth transition", "token_endpoint_auth_method", "none"}, {"wrong ID", "client_id", "another-client"},
		{"server token field", "registration_access_token", rat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := cloneMap(setup.body)
			body["client_id"] = clientID
			body[tc.field] = tc.value
			res := performTestRequest(t, GetTestServer(t).App, 0, http.MethodPut, clientPath, setup.host, "Bearer", rat, "application/json", CreateTestJSONRequestBody(t, body))
			defer res.Body.Close()
			AssertTestStatusCode(t, res, http.StatusBadRequest)
		})
	}

	testCases := []TestRequestCase[rfc7592Request]{
		{
			Name: "get registration",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{setup: setup, host: setup.host, path: clientPath}, rat
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, req rfc7592Request, res *http.Response) {
				body := decodeJSONObject(t, res)
				AssertEqual(t, res.Header.Get("Cache-Control"), "no-store")
				AssertEqual(t, jsonString(body["client_id"]), clientID)
				AssertEqual(t, jsonString(body["client_name"]), req.setup.clientName)
				AssertEqual(t, jsonString(body["client_secret"]), secret)
				AssertEqual(t, jsonString(body["registration_access_token"]), rat)
				AssertEqual(t, jsonString(body["registration_client_uri"]), requestURL(setup.host, clientPath))
			},
			Method: http.MethodGet,
		},
		{
			Name: "update registration",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				body := cloneMap(setup.body)
				body["client_name"] = updatedName
				body["client_id"] = clientID
				body["client_secret"] = secret
				delete(body, "logo_uri")
				return rfc7592Request{setup: setup, host: setup.host, path: clientPath, body: body}, rat
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ rfc7592Request, res *http.Response) {
				body := decodeJSONObject(t, res)
				AssertEqual(t, jsonString(body["client_name"]), updatedName)
				AssertEqual(t, jsonString(body["client_secret"]), secret)
				AssertEqual(t, jsonString(body["registration_access_token"]), rat)
				if jsonString(body["logo_uri"]) != "" {
					t.Fatal("omitted metadata was not cleared")
				}
			},
			Method: http.MethodPut,
		},
		{
			Name: "confirm update",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{setup: setup, host: setup.host, path: clientPath}, rat
			},
			ExpStatus: http.StatusOK,
			AssertFn: func(t *testing.T, _ rfc7592Request, res *http.Response) {
				AssertEqual(t, jsonString(decodeJSONObject(t, res)["client_name"]), updatedName)
			},
			Method: http.MethodGet,
		},
		{
			Name: "reject unknown client",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{host: setup.host, path: oauthRegisterClientPath("missing-client")}, rat
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  func(*testing.T, rfc7592Request, *http.Response) {},
			Method:    http.MethodGet,
		},
		{
			Name: "reject cross-host token",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{host: crossHost, path: clientPath}, rat
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  func(*testing.T, rfc7592Request, *http.Response) {},
			Method:    http.MethodGet,
		},
		{
			Name: "delete registration",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{host: setup.host, path: clientPath}, rat
			},
			ExpStatus: http.StatusNoContent,
			AssertFn:  func(*testing.T, rfc7592Request, *http.Response) {},
			Method:    http.MethodDelete,
		},
		{
			Name: "reject deleted client",
			ReqFn: func(t *testing.T) (rfc7592Request, string) {
				return rfc7592Request{host: setup.host, path: clientPath}, rat
			},
			ExpStatus: http.StatusUnauthorized,
			AssertFn:  func(*testing.T, rfc7592Request, *http.Response) {},
			Method:    http.MethodGet,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			tc.RequestBodyFn = func(req rfc7592Request) any { return req.body }
			tc.HostFn = func(req rfc7592Request) string { return req.host }
			tc.PathFromReqFn = func(req rfc7592Request) string { return req.path }
			PerformTestRequestCase(t, tc.Method, "", tc)
		})
	}
}

func TestOAuthDynamicRegistrationIATTokenExchange(t *testing.T) {
	ctx := context.Background()
	cacheStore := GetTestCache(t)

	setup := setupDynamicRegistration(t, false, false, false)
	verifier := utils.Base62UUID() + utils.Base62UUID()
	challenge := utils.Sha256HashBase64(verifier)
	code, err := cacheStore.GenerateAccountCredentialsRegistrationIATCode(ctx, cache.GenerateAccountCredentialsRegistrationIATCodeOptions{
		RequestID: uuid.NewString(), ClientID: setup.domain,
		AccountPublicID: setup.account.PublicID, AccountVersion: setup.account.Version(),
		Domain: setup.domain, Challenge: challenge,
	})
	if err != nil {
		t.Fatal(err)
	}

	testCase := TestRequestCase[string]{
		ReqFn: func(t *testing.T) (string, string) {
			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("client_id", setup.domain)
			form.Set("code_verifier", verifier)
			return form.Encode(), ""
		},
		ExpStatus: http.StatusOK,
		AssertFn: func(t *testing.T, _ string, res *http.Response) {
			AssertNotEmpty(t, jsonString(decodeJSONObject(t, res)["access_token"]))
		},
	}
	PerformTestRequestCaseWihURLEncodedBody(t, http.MethodPost, oauthIATTokenPath(), testCase)
}
