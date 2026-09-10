package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/net/publicsuffix"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type prepareDynamicRegistrationOptions struct {
	requestID                                                   string
	accountID                                                   int32
	accountPublicID                                             uuid.UUID
	data                                                        ApplicationRegistrationData
	softwareStatement, iatDomain, backendDomain, frontendDomain string
	app                                                         bool
}

// Merge verified claims by presence, including explicit false, zero and empty arrays.
// Unknown JWT claims are ignored by the typed metadata decoder.
func mergeRegistrationMetadata(body ApplicationRegistrationData, statement tokens.SoftwareStatementClaims) (ApplicationRegistrationData, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return ApplicationRegistrationData{}, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return ApplicationRegistrationData{}, err
	}
	if body.ResponseTypes != nil {
		fields["response_types"], _ = json.Marshal(body.ResponseTypes)
	}
	if body.GrantTypes != nil {
		fields["grant_types"], _ = json.Marshal(body.GrantTypes)
	}
	for name, value := range statement.RawMetadata {
		fields[name] = value
	}
	encoded, err = json.Marshal(fields)
	if err != nil {
		return ApplicationRegistrationData{}, err
	}
	var merged ApplicationRegistrationData
	if err := json.Unmarshal(encoded, &merged); err != nil {
		return ApplicationRegistrationData{}, err
	}
	return merged, nil
}

func (s *Services) prepareDynamicRegistration(ctx context.Context, opts prepareDynamicRegistrationOptions) (ApplicationRegistrationData, *exceptions.ServiceError) {
	data := opts.data
	var methods []database.SoftwareStatementVerificationMethod
	allowedScopes := allowedAccountCredentialsScopes
	if opts.app {
		account, err := s.GetAccountByID(ctx, GetAccountByIDOptions{RequestID: opts.requestID, ID: opts.accountID})
		if err != nil {
			return data, err
		}
		opts.accountPublicID = account.PublicID
		cfg, err := s.GetAndCacheAppDynamicRegistrationConfig(ctx, GetAndCacheAppDynamicRegistrationConfigOptions{RequestID: opts.requestID, AccountID: opts.accountID})
		if err != nil {
			return data, err
		}
		methods = cfg.SoftwareStatementVerificationMethods
		if len(cfg.DefaultAllowedScopes) > 0 {
			allowedScopes = utils.MapSlice(cfg.DefaultAllowedScopes, func(scope *database.Scopes) string { return string(*scope) })
		} else {
			allowedScopes = allowedAppScopes
		}
	} else {
		cfg, err := s.GetAndCacheAccountDynamicRegistrationConfig(ctx, GetAndCacheAccountDynamicRegistrationConfigOptions{RequestID: opts.requestID, AccountPublicID: opts.accountPublicID})
		if err != nil {
			return data, err
		}
		methods = cfg.SoftwareStatementVerificationMethods
	}
	if opts.softwareStatement != "" {
		// This preview only locates the account's configured verification key/domain.
		// No metadata from it is applied until signature verification succeeds.
		var preview jwt.MapClaims
		if _, _, err := jwt.NewParser().ParseUnverified(opts.softwareStatement, &preview); err != nil {
			return data, exceptions.NewInvalidTokenError("invalid software statement")
		}
		keyURI := data.ClientURI
		if claimURI, ok := preview["client_uri"].(string); ok {
			keyURI = claimURI
		}
		jwksURI := data.JWKsURI
		if claimJWKS, ok := preview["jwks_uri"].(string); ok && claimJWKS != "" {
			jwksURI = claimJWKS
		}
		domain := registrationDomain(keyURI, data.RedirectURIs, opts.iatDomain)
		base, err := publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return data, exceptions.NewInvalidTokenError("invalid software statement domain")
		}
		claims, standard, err := s.jwt.VerifySoftwareStatement(ctx, tokens.VerifySoftwareStatementOptions{
			RequestID: opts.requestID, SoftwareStatement: opts.softwareStatement,
			GetPublicJWK: s.buildDynamicRegistrationSoftwareStatementFunc(ctx, buildDynamicRegistrationSoftwareStatementFuncOptions{
				requestID: opts.requestID, accountPublicID: opts.accountPublicID, verificationMethods: methods,
				jwksURI: jwksURI, jwks: data.JWKs, domain: domain, baseDomain: base,
			}),
		})
		if err != nil {
			if errors.Is(err, errUnapprovedSoftwareStatement) {
				return data, exceptions.NewUnauthorizedTokenError("unapproved software statement")
			}
			return data, exceptions.NewInvalidTokenError("invalid software statement")
		}
		if serviceErr := s.verifySoftwareStatementSTDClaims(ctx, verifySoftwareStatementSTDClaimsOptions{
			requestID: opts.requestID, domain: domain, baseDomain: base, backendDomain: opts.backendDomain, frontendDomain: opts.frontendDomain, claims: &standard,
		}); serviceErr != nil {
			return data, serviceErr
		}
		if serviceErr := s.validateSoftwareStatementClaims(ctx, validateSoftwareStatementClaimsOptions{
			requestID: opts.requestID, claims: &claims, allowedScopes: utils.SliceToHashSet(allowedScopes),
		}); serviceErr != nil {
			return data, exceptions.NewInvalidTokenError("invalid software statement")
		}
		data, err = mergeRegistrationMetadata(data, claims)
		if err != nil {
			return data, exceptions.NewInvalidTokenError("invalid software statement metadata")
		}
	}
	if data.ApplicationType == "" {
		if opts.app {
			data.ApplicationType = "web"
		} else if slices.Contains(data.GrantTypes, "client_credentials") {
			data.ApplicationType = "service"
		} else {
			data.ApplicationType = "native"
		}
	}
	if data.ClientName == "" {
		data.ClientName = "Client " + utils.Base62UUID()
	}
	if data.ClientURI == "" {
		domain := registrationDomain("", data.RedirectURIs, opts.iatDomain)
		if domain == "" {
			return data, exceptions.NewValidationError("a client domain could not be determined")
		}
		data.ClientURI = "https://" + domain
	}
	if data.Scope == "" && !opts.app {
		data.Scope = "profile"
	}
	if err := normalizeRegistrationMetadata(&data); err != nil {
		return data, err
	}
	if err := s.validate.StructCtx(ctx, &data); err != nil {
		return data, exceptions.NewValidationError("invalid client metadata")
	}
	return data, nil
}

func registrationDomain(clientURI string, redirects []string, fallback string) string {
	if parsed, err := url.Parse(clientURI); err == nil && parsed.Hostname() != "" {
		return parsed.Hostname()
	}
	if fallback != "" {
		return fallback
	}
	for _, redirect := range redirects {
		if parsed, err := url.Parse(redirect); err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
	}
	return ""
}

func normalizeRegistrationMetadata(data *ApplicationRegistrationData) *exceptions.ServiceError {
	if data.GrantTypes == nil {
		data.GrantTypes = []string{"authorization_code"}
	}
	if data.ResponseTypes == nil {
		data.ResponseTypes = []string{"code"}
	}
	if data.TokenEndpointAuthMethod == "" {
		data.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if len(data.GrantTypes) == 0 {
		return exceptions.NewValidationError("grant_types must not be empty")
	}
	codeGrant := slices.Contains(data.GrantTypes, "authorization_code")
	for _, response := range data.ResponseTypes {
		if slices.Contains(strings.Fields(response), "code") && !codeGrant {
			return exceptions.NewValidationError("code responses require authorization_code")
		}
	}
	if codeGrant && !slices.ContainsFunc(data.ResponseTypes, func(response string) bool { return slices.Contains(strings.Fields(response), "code") }) {
		return exceptions.NewValidationError("authorization_code requires a code response")
	}
	if codeGrant && len(data.RedirectURIs) == 0 {
		return exceptions.NewError(exceptions.OAuthErrorInvalidRedirectURI, "redirect_uris is required for authorization_code")
	}
	for _, raw := range data.RedirectURIs {
		uri, err := url.Parse(raw)
		if err != nil || uri.Scheme == "" || uri.User != nil || strings.Contains(raw, "#") || ((uri.Scheme == "https" || uri.Scheme == "http") && uri.Host == "") {
			return exceptions.NewError(exceptions.OAuthErrorInvalidRedirectURI, "invalid redirect URI")
		}
	}
	if data.JWKs != nil && data.JWKsURI != "" {
		return exceptions.NewValidationError("jwks and jwks_uri are mutually exclusive")
	}
	if data.JWKs != nil {
		if len(data.JWKs.Keys) == 0 {
			return exceptions.NewValidationError("jwks must contain keys")
		}
		for _, key := range data.JWKs.Keys {
			if key == nil {
				return exceptions.NewValidationError("invalid public JWK")
			}
			if _, err := key.ToUsableKey(); err != nil {
				return exceptions.NewValidationError("invalid public JWK")
			}
			raw, err := key.MarshalJSON()
			if err != nil {
				return exceptions.NewValidationError("invalid public JWK")
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &fields) != nil {
				return exceptions.NewValidationError("invalid public JWK")
			}
			for _, secret := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
				if _, found := fields[secret]; found {
					return exceptions.NewValidationError("jwks must contain only public keys")
				}
			}
		}
	}
	if data.JWKsURI != "" {
		uri, err := url.Parse(data.JWKsURI)
		if err != nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" {
			return exceptions.NewValidationError("jwks_uri must be an HTTPS URL")
		}
	}
	return nil
}

func mapRegistrationResponseTypes(values []string) ([]database.ResponseType, *exceptions.ServiceError) {
	if values != nil && len(values) == 0 {
		return []database.ResponseType{}, nil
	}
	return mapResponseTypesWithDefault(values)
}
