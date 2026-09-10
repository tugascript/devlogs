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
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
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

func doJSONRequest(t *testing.T, method, rawURL, accessToken string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, rawURL, reader)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	res, err := GetTestServer(t).App.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
	if err != nil {
		t.Fatal(err)
	}
	return res
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

func postRegister(t *testing.T, setup dcrSetup) *http.Response {
	t.Helper()
	return doJSONRequest(t, http.MethodPost, requestURL(setup.host, oauthRegisterPath()), setup.accessToken, setup.body)
}

func assertCreatedRegistration(t *testing.T, setup dcrSetup, res *http.Response) (clientID, rat, registrationURI string) {
	t.Helper()
	defer res.Body.Close()
	response := decodeJSONObject(t, res)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
	}
	clientID = jsonString(response["client_id"])
	returnedName := jsonString(response["client_name"])
	scope := jsonString(response["scope"])
	version := jsonString(response["software_version"])
	returnedStatement := jsonString(response["software_statement"])
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
	return clientID, rat, registrationURI
}

// Exercise the actual HTTP route, IAT verification, software-statement trust,
// credential issuance and database persistence together.
func TestDynamicRegistration(t *testing.T) {
	for _, appClient := range []bool{true, false} {
		for _, bounded := range []bool{false, true} {
			if !appClient && !bounded {
				continue
			} // Account registration is protected by policy.
			for _, statement := range []bool{false, true} {
				t.Run(fmt.Sprintf("app=%t/iat=%t/statement=%t", appClient, bounded, statement), func(t *testing.T) {
					setup := setupDynamicRegistration(t, appClient, bounded, statement)
					res := postRegister(t, setup)
					assertCreatedRegistration(t, setup, res)
				})
			}
		}
	}
}

func TestDynamicRegistrationIATHostIsolation(t *testing.T) {
	cfg := GetTestConfig(t)

	t.Run("account IAT cannot register an app", func(t *testing.T) {
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
		res := postRegister(t, setup)
		defer res.Body.Close()
		response := decodeJSONObject(t, res)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
		}
		if jsonString(response["error"]) != exceptions.OAuthErrorAccessDenied {
			t.Fatalf("error=%s", response["error"])
		}
	})

	t.Run("app IAT cannot register account credentials", func(t *testing.T) {
		setup := setupDynamicRegistration(t, true, true, false)
		setup.host = cfg.BackendDomain()
		setup.body["application_type"] = "native"
		res := postRegister(t, setup)
		defer res.Body.Close()
		response := decodeJSONObject(t, res)
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
		}
		if jsonString(response["error"]) != exceptions.OAuthErrorAccessDenied {
			t.Fatalf("error=%s", response["error"])
		}
	})
}

func TestDynamicRegistrationSoftwareStatementFailures(t *testing.T) {
	setup := setupDynamicRegistration(t, true, false, false)
	goodPrivate, goodKid, goodJWK := generateEd25519JWK(t)
	goodJSON, err := json.Marshal(goodJWK)
	if err != nil {
		t.Fatal(err)
	}
	approveSoftwareStatementKey(t, setup.account, goodJSON, goodKid, database.CredentialsUsageApp)

	cases := []struct {
		name      string
		statement string
		wantError string
	}{
		{
			name: "bad signature",
			statement: func() string {
				badPrivate, _, _ := generateEd25519JWK(t)
				return signSoftwareStatement(t, badPrivate, goodKid, jwt.MapClaims{
					"iss": "https://" + setup.domain, "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})
			}(),
			wantError: exceptions.OAuthErrorInvalidSoftwareStatement,
		},
		{
			name: "unapproved kid",
			statement: func() string {
				private, kid, _ := generateEd25519JWK(t)
				return signSoftwareStatement(t, private, kid, jwt.MapClaims{
					"iss": "https://" + setup.domain, "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
				})
			}(),
			wantError: exceptions.OAuthErrorUnapprovedSoftwareStatement,
		},
		{
			name: "issuer mismatch",
			statement: signSoftwareStatement(t, goodPrivate, goodKid, jwt.MapClaims{
				"iss": "https://unrelated.example.net", "client_name": setup.clientName, "client_uri": "https://" + setup.domain,
			}),
			wantError: exceptions.OAuthErrorUnapprovedSoftwareStatement,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := cloneMap(setup.body)
			body["software_statement"] = tc.statement
			res := doJSONRequest(t, http.MethodPost, requestURL(setup.host, oauthRegisterPath()), "", body)
			defer res.Body.Close()
			response := decodeJSONObject(t, res)
			if res.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
			}
			if jsonString(response["error"]) != tc.wantError {
				t.Fatalf("error=%s want %s", response["error"], tc.wantError)
			}
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

	t.Run("app", func(t *testing.T) {
		setup := setupDynamicRegistration(t, true, false, false)
		res := postRegister(t, setup)
		clientID, rat, registrationURI := assertCreatedRegistration(t, setup, res)
		if registrationURI != requestURL(setup.host, oauthRegisterClientPath(clientID)) {
			t.Fatalf("registration_client_uri=%q", registrationURI)
		}
		assertRFC7592Lifecycle(t, setup, clientID, rat, cfg.BackendDomain())
	})

	t.Run("account credentials", func(t *testing.T) {
		setup := setupDynamicRegistration(t, false, true, false)
		res := postRegister(t, setup)
		clientID, rat, _ := assertCreatedRegistration(t, setup, res)
		assertRFC7592Lifecycle(t, setup, clientID, rat, cfg.BackendDomain())
	})

	t.Run("well-known registration_endpoint", func(t *testing.T) {
		account := CreateTestAccount(t, GenerateFakeAccountData(t, services.AuthProviderLocal))
		cleanupAccount(t, account)
		host := account.Username + "." + cfg.BackendDomain()
		res := doJSONRequest(t, http.MethodGet, requestURL(host, paths.WellKnownBase+paths.WellKnownOIDC), "", nil)
		defer res.Body.Close()
		response := decodeJSONObject(t, res)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
		}
		want := requestURL(host, oauthRegisterPath())
		if jsonString(response["registration_endpoint"]) != want {
			t.Fatalf("registration_endpoint=%s want %s", response["registration_endpoint"], want)
		}
	})
}

func assertRFC7592Lifecycle(t *testing.T, setup dcrSetup, clientID, rat, backendDomain string) {
	t.Helper()
	clientURL := requestURL(setup.host, oauthRegisterClientPath(clientID))

	getRes := doJSONRequest(t, http.MethodGet, clientURL, rat, nil)
	defer getRes.Body.Close()
	getBody := decodeJSONObject(t, getRes)
	if getRes.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d error=%s", getRes.StatusCode, getBody["error"])
	}
	if getRes.Header.Get("Cache-Control") != "no-store" {
		t.Error("GET response is cacheable")
	}
	if jsonString(getBody["client_id"]) != clientID || jsonString(getBody["client_name"]) != setup.clientName {
		t.Fatalf("GET metadata mismatch: %s", getBody["client_name"])
	}
	if _, ok := getBody["client_secret"]; ok {
		t.Fatal("GET must not return client_secret")
	}
	if _, ok := getBody["registration_access_token"]; ok {
		t.Fatal("GET must not return registration_access_token")
	}

	updatedName := "Updated " + setup.clientName
	putBody := cloneMap(setup.body)
	putBody["client_name"] = updatedName
	putRes := doJSONRequest(t, http.MethodPut, clientURL, rat, putBody)
	defer putRes.Body.Close()
	putResponse := decodeJSONObject(t, putRes)
	if putRes.StatusCode != http.StatusOK {
		t.Fatalf("PUT status=%d error=%s", putRes.StatusCode, putResponse["error"])
	}
	if jsonString(putResponse["client_name"]) != updatedName {
		t.Fatalf("PUT did not update client_name: %s", putResponse["client_name"])
	}
	if _, ok := putResponse["client_secret"]; ok {
		t.Fatal("PUT must not return client_secret")
	}

	confirm := doJSONRequest(t, http.MethodGet, clientURL, rat, nil)
	defer confirm.Body.Close()
	confirmBody := decodeJSONObject(t, confirm)
	if jsonString(confirmBody["client_name"]) != updatedName {
		t.Fatal("updated name was not persisted")
	}

	unknown := doJSONRequest(t, http.MethodGet, requestURL(setup.host, oauthRegisterClientPath("missing-client")), rat, nil)
	defer unknown.Body.Close()
	if unknown.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown client status=%d", unknown.StatusCode)
	}

	crossHost := backendDomain
	if !setup.appClient {
		crossHost = setup.account.Username + "." + backendDomain
	}
	cross := doJSONRequest(t, http.MethodGet, requestURL(crossHost, oauthRegisterClientPath(clientID)), rat, nil)
	defer cross.Body.Close()
	if cross.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-host RAT status=%d", cross.StatusCode)
	}

	delRes := doJSONRequest(t, http.MethodDelete, clientURL, rat, nil)
	defer delRes.Body.Close()
	if delRes.StatusCode != http.StatusNoContent {
		t.Fatalf("DELETE status=%d", delRes.StatusCode)
	}
	after := doJSONRequest(t, http.MethodGet, clientURL, rat, nil)
	defer after.Body.Close()
	if after.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET after DELETE status=%d", after.StatusCode)
	}
}

func TestOAuthDynamicRegistrationIATTokenExchange(t *testing.T) {
	ctx := context.Background()
	cfg := GetTestConfig(t)
	cacheStore := GetTestCache(t)

	for _, appClient := range []bool{false, true} {
		t.Run(fmt.Sprintf("app=%t", appClient), func(t *testing.T) {
			setup := setupDynamicRegistration(t, appClient, false, false)
			verifier := utils.Base62UUID() + utils.Base62UUID()
			challenge := utils.Sha256HashBase64(verifier)
			hostUsername := ""
			if appClient {
				hostUsername = setup.account.Username
			}
			code, err := cacheStore.GenerateAccountCredentialsRegistrationIATCode(ctx, cache.GenerateAccountCredentialsRegistrationIATCodeOptions{
				HostUsername: hostUsername, RequestID: uuid.NewString(), ClientID: setup.domain,
				AccountPublicID: setup.account.PublicID, AccountVersion: setup.account.Version(),
				Domain: setup.domain, Challenge: challenge,
			})
			if err != nil {
				t.Fatal(err)
			}

			form := url.Values{}
			form.Set("grant_type", "authorization_code")
			form.Set("code", code)
			form.Set("client_id", setup.domain)
			form.Set("code_verifier", verifier)
			req := httptest.NewRequest(http.MethodPost, requestURL(setup.host, oauthIATTokenPath()), strings.NewReader(form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			res, err := GetTestServer(t).App.Test(req, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			response := decodeJSONObject(t, res)
			if res.StatusCode != http.StatusOK {
				t.Fatalf("status=%d error=%s", res.StatusCode, response["error"])
			}
			accessToken := jsonString(response["access_token"])
			if accessToken == "" {
				t.Fatal("missing access_token")
			}

			wrongHost := setup.account.Username + "." + cfg.BackendDomain()
			if appClient {
				wrongHost = cfg.BackendDomain()
			}
			mismatchCode, err := cacheStore.GenerateAccountCredentialsRegistrationIATCode(ctx, cache.GenerateAccountCredentialsRegistrationIATCodeOptions{
				HostUsername: hostUsername, RequestID: uuid.NewString(), ClientID: setup.domain,
				AccountPublicID: setup.account.PublicID, AccountVersion: setup.account.Version(),
				Domain: setup.domain, Challenge: challenge,
			})
			if err != nil {
				t.Fatal(err)
			}
			form.Set("code", mismatchCode)
			badReq := httptest.NewRequest(http.MethodPost, requestURL(wrongHost, oauthIATTokenPath()), strings.NewReader(form.Encode()))
			badReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			badRes, err := GetTestServer(t).App.Test(badReq, fiber.TestConfig{Timeout: 30 * time.Second, FailOnTimeout: true})
			if err != nil {
				t.Fatal(err)
			}
			defer badRes.Body.Close()
			if badRes.StatusCode != http.StatusUnauthorized {
				t.Fatalf("cross-host token exchange status=%d", badRes.StatusCode)
			}
		})
	}
}
