package cache

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type registrationTestStorage struct {
	values    map[string][]byte
	ttls      map[string]time.Duration
	deleteErr error
}

func (s *registrationTestStorage) GetWithContext(_ context.Context, key string) ([]byte, error) {
	return s.values[key], nil
}

func (s *registrationTestStorage) SetWithContext(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.values[key] = value
	s.ttls[key] = ttl
	return nil
}

func (s *registrationTestStorage) DeleteWithContext(_ context.Context, key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	delete(s.values, key)
	return nil
}

func TestDynamicRegistrationFlows(t *testing.T) {
	ctx := context.Background()
	storage := &registrationTestStorage{values: map[string][]byte{}, ttls: map[string]time.Duration{}}
	c := &Cache{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), oauthStateTTL: time.Minute, oauthCodeTTL: 30 * time.Second}
	flows := []dynamicRegistrationCache{c.accountCredentialsDynamicRegistration(), c.appsDynamicRegistration("one.example"), c.appsDynamicRegistration("two.example")}
	for i := range flows {
		flows[i].storage = storage
	}
	for _, flow := range flows {
		t.Run(flow.prefix, func(t *testing.T) {
			token, err := flow.SaveDynamicRegistrationIATLoginCSRF(ctx, SaveDynamicRegistrationIATLoginCSRFOptions{Domain: "example.com", ClientID: "client"})
			if err != nil {
				t.Fatal(err)
			}
			key := flow.prefix + ":login:example.com:client"
			if storage.ttls[key] != time.Minute || string(storage.values[key]) == token {
				t.Fatal("CSRF TTL or hashing changed")
			}
			opts := VerifyDynamicRegistrationIATLoginCSRFOptions{Domain: "example.com", ClientID: "client", CSRFToken: "wrong"}
			if ok, err := flow.VerifyDynamicRegistrationIATLoginCSRF(ctx, opts); ok || err != nil {
				t.Fatalf("wrong token: %v %v", ok, err)
			}
			opts.CSRFToken = token
			if ok, err := flow.VerifyDynamicRegistrationIATLoginCSRF(ctx, opts); !ok || err != nil {
				t.Fatalf("valid token: %v %v", ok, err)
			}
			if ok, err := flow.VerifyDynamicRegistrationIATLoginCSRF(ctx, opts); ok || err != nil {
				t.Fatalf("replayed token: %v %v", ok, err)
			}

			id := uuid.New()
			code, err := flow.GenerateDynamicRegistrationIATCode(ctx, GenerateDynamicRegistrationIATCodeOptions{AccountPublicID: id, AccountVersion: 3, ClientID: "client", Domain: "example.com", Challenge: "challenge"})
			if err != nil {
				t.Fatal(err)
			}
			codeKey := flow.prefix + ":code:" + strings.Split(code, "-")[0]
			if storage.ttls[codeKey] != 30*time.Second {
				t.Fatal("code TTL changed")
			}
			for _, other := range flows {
				if other.prefix == flow.prefix {
					continue
				}
				if _, ok, err := other.VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{Code: code}); ok || err != nil {
					t.Fatal("code crossed registration scopes")
				}
			}
			data, ok, err := flow.VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{Code: code})
			if err != nil || !ok || data.AccountPublicID != id || data.AccountVersion != 3 || data.Challenge != "challenge" {
				t.Fatalf("code round trip: %+v %v %v", data, ok, err)
			}
			if _, ok, err := flow.VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{Code: code}); ok || err != nil {
				t.Fatal("code replay accepted")
			}

			session, err := flow.CreateDynamicRegistrationSessionKey(ctx, CreateDynamicRegistrationSessionKeyOptions{AccountPublicID: id, AccountVersion: 3, ClientID: "client", Domain: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				data, client, valid, found, err := flow.VerifyDynamicRegistrationSessionKey(ctx, VerifyDynamicRegistrationSessionKeyOptions{Domain: "example.com", SessionKey: session})
				if err != nil || !valid || !found || client != "client" || data.AccountPublicID != id {
					t.Fatalf("session round trip: %+v %s %v %v %v", data, client, valid, found, err)
				}
			}
			_, client, valid, found, err := flow.VerifyDynamicRegistrationSessionKey(ctx, VerifyDynamicRegistrationSessionKeyOptions{Domain: "example.com", SessionKey: "client.wrong"})
			if err != nil || valid || !found || client != "client" {
				t.Fatal("invalid session flags changed")
			}
			_, _, valid, found, err = flow.VerifyDynamicRegistrationSessionKey(ctx, VerifyDynamicRegistrationSessionKeyOptions{Domain: "other.example", SessionKey: session})
			if err != nil || valid || found {
				t.Fatal("session crossed domains")
			}

			storage.values[flow.prefix+":code:corrupt"] = []byte("{")
			if _, ok, err := flow.VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{Code: "corrupt.secret"}); ok || err != nil {
				t.Fatal("malformed code accepted")
			}
			if _, ok, err := flow.VerifyDynamicRegistrationIATCode(ctx, VerifyDynamicRegistrationIATCodeOptions{Code: "corrupt-secret"}); ok || err == nil {
				t.Fatal("corrupt JSON error lost")
			}

			csrf, err := flow.SaveDynamicRegistrationIAT2FACSRFToken(ctx, SaveDynamicRegistrationIAT2FACSRFTokenOptions{SessionID: "session", TwoFATTL: 42})
			if err != nil {
				t.Fatal(err)
			}
			if storage.ttls[buildDynamicRegistrationIAT2FACSRFCacheKey(flow.prefix, "session")] != 42*time.Second {
				t.Fatal("2FA TTL changed")
			}
			storage.deleteErr = errors.New("delete failed")
			if ok, err := flow.VerifyDynamicRegistrationIAT2FACSRFToken(ctx, VerifyDynamicRegistrationIAT2FACSRFTokenOptions{SessionID: "session", CSRFToken: csrf}); ok || !errors.Is(err, storage.deleteErr) {
				t.Fatal("delete failure lost")
			}
			storage.deleteErr = nil
		})
	}
}

func TestDynamicRegistrationAuthPayloads(t *testing.T) {
	ctx := context.Background()
	storage := &registrationTestStorage{values: map[string][]byte{}, ttls: map[string]time.Duration{}}
	c := &Cache{logger: slog.New(slog.NewTextHandler(io.Discard, nil)), oauthStateTTL: time.Minute}
	flow := c.appsDynamicRegistration("example.com")
	flow.storage = storage
	want := AppsDynamicRegistrationIATAuthData{AccountID: 42, Domain: "domain", State: "state", Challenge: "challenge", RedirectURI: "redirect"}
	client, err := flow.saveAuth(ctx, c.logger, want)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := getDynamicRegistrationAuth[AppsDynamicRegistrationIATAuthData](ctx, flow, c.logger, client)
	if err != nil || !ok || got != want {
		t.Fatalf("auth round trip: %+v %v %v", got, ok, err)
	}
	account := c.accountCredentialsDynamicRegistration()
	account.storage = storage
	if _, ok, err := getDynamicRegistrationAuth[AccountCredentialsDynamicRegistrationIATAuthData](ctx, account, c.logger, client); ok || err != nil {
		t.Fatal("auth crossed scopes")
	}
	client, err = account.saveAuth(ctx, c.logger, AccountCredentialsDynamicRegistrationIATAuthData{Domain: "domain"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storage.values[account.prefix+":auth:"+client]), "account_id") {
		t.Fatal("account credentials JSON schema changed")
	}
}
