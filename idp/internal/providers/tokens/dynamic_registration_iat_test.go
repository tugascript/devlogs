package tokens

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

func TestDynamicRegistrationIATBindings(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := utils.EncodeEd25519Jwk(public, "test")
	provider := &Tokens{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), dynamicRegistrationTTL: 300}
	accountID := uuid.New()
	for _, tc := range []struct {
		name, issuer, verifier string
		usage                  DynamicRegistrationUsage
		verifyUsage            DynamicRegistrationUsage
		tokenUse               DynamicRegistrationTokenUse
		verifyUse              DynamicRegistrationTokenUse
		change                 func(*dynamicRegistrationTokenClaims)
		wantError              bool
	}{
		{name: "account credentials", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount},
		{name: "apps", issuer: "alice.id.example.com", verifier: "alice.id.example.com", usage: DynamicRegistrationUsageApp, verifyUsage: DynamicRegistrationUsageApp},
		{name: "account token cannot register app", issuer: "id.example.com", verifier: "alice.id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageApp, wantError: true},
		{name: "app token cannot register account credentials", issuer: "alice.id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageApp, verifyUsage: DynamicRegistrationUsageAccount, wantError: true},
		{name: "usage claim mismatch", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageApp, wantError: true},
		{name: "iat cannot be used as registration access token", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, verifyUse: DynamicRegistrationTokenUseRegistration, wantError: true},
		{name: "other tenant", issuer: "alice.id.example.com", verifier: "bob.id.example.com", usage: DynamicRegistrationUsageApp, verifyUsage: DynamicRegistrationUsageApp, wantError: true},
		{name: "missing expiry", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) { c.ExpiresAt = nil }, wantError: true},
		{name: "expired", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) {
			c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		}, wantError: true},
		{name: "wrong audience", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) {
			c.Audience = []string{"https://elsewhere.example.com"}
		}, wantError: true},
		{name: "issuer path", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) { c.Issuer += "/other" }, wantError: true},
		{name: "missing account", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) { c.AccountID = uuid.Nil }, wantError: true},
		{name: "missing domain", issuer: "id.example.com", verifier: "id.example.com", usage: DynamicRegistrationUsageAccount, verifyUsage: DynamicRegistrationUsageAccount, change: func(c *dynamicRegistrationTokenClaims) { c.Subject = "" }, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenUse := tc.tokenUse
			if tokenUse == "" {
				tokenUse = DynamicRegistrationTokenUseInitialAccess
			}
			verifyUse := tc.verifyUse
			if verifyUse == "" {
				verifyUse = DynamicRegistrationTokenUseInitialAccess
			}
			token := provider.DynamicRegistrationIAT(DynamicRegistrationIATOptions{
				AccountPublicID: accountID, AccountVersion: 1, IssuerDomain: tc.issuer,
				Subject: "client.example.com", JTI: "registration", Usage: tc.usage, TokenUse: tokenUse,
			})
			claims := token.Claims.(dynamicRegistrationTokenClaims)
			if tc.change != nil {
				tc.change(&claims)
			}
			token.Claims = claims
			token.Header["kid"] = "test"
			signed, err := token.SignedString(private)
			if err != nil {
				t.Fatal(err)
			}
			domain, account, err := provider.VerifyDynamicRegistrationIAT(context.Background(), VerifyDynamicRegistrationIATOptions{
				IAT: signed, IssuerDomain: tc.verifier, Usage: tc.verifyUsage, TokenUse: verifyUse,
				GetPublicJWK: func(string, utils.SupportedCryptoSuite) (utils.JWK, error) { return &jwk, nil },
			})
			if (err != nil) != tc.wantError {
				t.Fatalf("error = %v, wantError = %v", err, tc.wantError)
			}
			if !tc.wantError && (domain != "client.example.com" || account.AccountID != accountID) {
				t.Fatalf("incorrect bindings: %s, %+v", domain, account)
			}
		})
	}
}
