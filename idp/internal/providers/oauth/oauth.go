package oauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/tugascript/devlogs/idp/internal/config"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

type oauthScopes struct {
	email    string
	profile  string
	birthday string
	location string
	gender   string
}

type Scope = string

const (
	logLayer string = "providers/oauth"

	ScopeProfile  Scope = "profile"
	ScopeBirthday Scope = "birthday"
	ScopeLocation Scope = "location"
	ScopeGender   Scope = "gender"
)

type Providers struct {
	gitHub    oauth2.Config
	google    oauth2.Config
	facebook  oauth2.Config
	apple     oauth2.Config
	microsoft oauth2.Config
	logger    *slog.Logger
}

func mapScopes(scopes []Scope, oas oauthScopes) []string {
	scopeMapper := make(map[string]bool)

	for _, s := range scopes {
		switch s {
		case ScopeBirthday:
			scopeMapper[oas.birthday] = true
		case ScopeGender:
			scopeMapper[oas.gender] = true
		case ScopeLocation:
			scopeMapper[oas.location] = true
		case ScopeProfile:
			scopeMapper[oas.location] = true
		}
	}

	mappedScopes := make([]string, 0, len(scopeMapper))
	for k := range scopeMapper {
		if k != "" {
			mappedScopes = append(mappedScopes, k)
		}
	}

	return mappedScopes
}

func appendScopes(cfg oauth2.Config, scopes []string) oauth2.Config {
	cfg.Scopes = append(cfg.Scopes, scopes...)
	return cfg
}

func GenerateState() (string, error) {
	bytes := make([]byte, 16)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return hex.EncodeToString(bytes), nil
}

func getConfig(cfg oauth2.Config, redirectURL string, oas oauthScopes, scopes []Scope) oauth2.Config {
	cfg.RedirectURL = redirectURL

	if scopes != nil {
		return appendScopes(cfg, mapScopes(scopes, oas))
	}

	return cfg
}

type getAccessTokenOptions struct {
	logger      *slog.Logger
	cfg         oauth2.Config
	redirectURL string
	oas         oauthScopes
	scopes      []Scope
	code        string
}

func getAccessToken(ctx context.Context, opts getAccessTokenOptions) (string, error) {
	opts.logger.DebugContext(ctx, "Getting access token...")

	cfg := getConfig(opts.cfg, opts.redirectURL, opts.oas, opts.scopes)
	token, err := cfg.Exchange(ctx, opts.code)
	if err != nil {
		opts.logger.ErrorContext(ctx, "Failed to exchange the code for a token", "error", err)
		return "", err
	}

	opts.logger.DebugContext(ctx, "Access token exchanged successfully")
	return token.AccessToken, nil
}

type getAuthorizationURLOptions struct {
	logger      *slog.Logger
	cfg         oauth2.Config
	redirectURL string
	oas         oauthScopes
	scopes      []Scope
}

func getAuthorizationURL(ctx context.Context, opts getAuthorizationURLOptions) (string, string, error) {
	opts.logger.DebugContext(ctx, "Getting authorization url...")

	state, err := GenerateState()
	if err != nil {
		opts.logger.ErrorContext(ctx, "Failed to generate state", "error", err)
		return "", "", err
	}

	cfg := getConfig(opts.cfg, opts.redirectURL, opts.oas, opts.scopes)
	url := cfg.AuthCodeURL(state)
	opts.logger.DebugContext(ctx, "Authorization url generated successfully")
	return url, state, nil
}

func NewProviders(
	log *slog.Logger,
	githubCfg,
	googleCfg,
	facebookCfg,
	appleCfg,
	microsoftCfg config.OAuthProviderConfig,
) *Providers {
	return &Providers{
		gitHub: oauth2.Config{
			ClientID:     githubCfg.ClientID(),
			ClientSecret: githubCfg.ClientSecret(),
			Endpoint:     github.Endpoint,
			Scopes:       []string{gitHubScopes.email},
		},
		google: oauth2.Config{
			ClientID:     googleCfg.ClientID(),
			ClientSecret: googleCfg.ClientSecret(),
			Endpoint:     google.Endpoint,
			Scopes:       []string{googleScopes.email},
		},
		facebook: oauth2.Config{
			ClientID:     facebookCfg.ClientID(),
			ClientSecret: facebookCfg.ClientSecret(),
			Endpoint:     facebook.Endpoint,
			Scopes:       []string{googleScopes.email},
		},
		apple: oauth2.Config{
			ClientID:     appleCfg.ClientID(),
			ClientSecret: appleCfg.ClientSecret(),
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://appleid.apple.com/auth/authorize",
				TokenURL: "https://appleid.apple.com/auth/token",
			},
			Scopes: []string{appleScopes.email},
		},
		microsoft: oauth2.Config{
			ClientID:     microsoftCfg.ClientID(),
			ClientSecret: microsoftCfg.ClientSecret(),
			Endpoint:     microsoft.LiveConnectEndpoint,
			Scopes:       []string{microsoftScopes.email},
		},
		logger: log,
	}
}

func getUserResponse(logger *slog.Logger, ctx context.Context, url, token string) ([]byte, int, error) {
	logger.DebugContext(ctx, "Getting user data...", "url", url)

	logger.DebugContext(ctx, "Building user data request")
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build user data request")
		return nil, 0, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	logger.DebugContext(ctx, "Requesting user data...")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to request the user data")
		return nil, 0, err
	}

	if res.StatusCode != http.StatusOK {
		logger.ErrorContext(ctx, "Responded with a non 200 OK status", "status", res.StatusCode)
		return nil, res.StatusCode, errors.New("status code is not 200 OK")
	}

	logger.DebugContext(ctx, "Reading the body")
	body, err := io.ReadAll(res.Body)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read the body", "error", err)
		return nil, 0, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			logger.ErrorContext(ctx, "Failed to close response body", "error", err)
		}
	}()

	return body, res.StatusCode, nil
}

type UserLocation struct {
	City    string
	Region  string
	Country string
}

type UserData struct {
	Name       string
	FirstName  string
	LastName   string
	Username   string
	Picture    string
	Email      string
	Gender     string
	Location   UserLocation
	BirthDate  string
	IsVerified bool
}

type ToUserData interface {
	ToUserData() UserData
}

type extraParams struct {
	params string
}

func (p *extraParams) addParam(prm string) {
	if p.params != "" {
		p.params = p.params + "," + prm
		return
	}

	p.params += prm
}

func (p *extraParams) isEmpty() bool {
	return p.params == ""
}

type AccessTokenOptions struct {
	RequestID   string
	Code        string
	RedirectURL string
	Scopes      []Scope
}

type AuthorizationURLOptions struct {
	RequestID   string
	RedirectURL string
	Scopes      []Scope
}

type UserDataOptions struct {
	RequestID string
	Token     string
	Scopes    []Scope
}
