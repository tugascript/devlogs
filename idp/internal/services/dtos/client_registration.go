package dtos

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/tugascript/devlogs/idp/internal/controllers/paths"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

// ClientRegistrationDTO is the RFC 7591 wire representation, independent of management DTOs.
type ClientRegistrationDTO struct {
	tokens.SoftwareStatementClaims
	ClientID                string    `json:"client_id"`
	ClientIDIssuedAt        int64     `json:"client_id_issued_at"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int64    `json:"client_secret_expires_at,omitempty"`
	SoftwareStatement       string    `json:"software_statement,omitempty"`
	ClientSecretJWK         utils.JWK `json:"client_secret_jwk,omitempty"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string    `json:"registration_client_uri,omitempty"`
}

func (r ClientRegistrationDTO) MarshalJSON() ([]byte, error) {
	type wire ClientRegistrationDTO
	raw, err := json.Marshal(wire(r))
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["response_types"], err = json.Marshal(r.ResponseTypes)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

func RegistrationClientURI(issuerDomain, clientID string) string {
	return fmt.Sprintf("https://%s%s%s%s%s/%s", issuerDomain, paths.V1, paths.AuthBase, paths.OAuthBase, paths.OAuthRegister, clientID)
}

func (r *ClientRegistrationDTO) WithRegistrationAccess(token, clientURI string) *ClientRegistrationDTO {
	if r == nil {
		return r
	}
	r.RegistrationAccessToken = token
	r.RegistrationClientURI = clientURI
	return r
}

func (r *ClientRegistrationDTO) WithoutSecrets() *ClientRegistrationDTO {
	if r == nil {
		return r
	}
	clone := *r
	clone.ClientSecret = ""
	clone.ClientSecretExpiresAt = nil
	clone.ClientSecretJWK = nil
	clone.RegistrationAccessToken = ""
	return &clone
}

func registrationFromApp(row *database.App, statement, secret string, expiry time.Time, key utils.JWK) *ClientRegistrationDTO {
	metadata := tokens.SoftwareStatementClaims{
		RedirectURIs:                 row.RedirectUris,
		TokenEndpointAuthMethod:      string(row.TokenEndpointAuthMethod),
		GrantTypes:                   utils.MapSlice(row.GrantTypes, func(v *database.GrantType) string { return string(*v) }),
		ResponseTypes:                utils.MapSlice(row.ResponseTypes, func(v *database.ResponseType) string { return string(*v) }),
		ApplicationType:              string(row.AppType),
		ClientName:                   row.ClientName,
		ClientURI:                    row.ClientUri,
		LogoURI:                      row.LogoUri.String,
		Scope:                        strings.Join(mapScopes(row.Scopes, row.CustomScopes), " "),
		Contacts:                     row.Contacts,
		TOSURI:                       row.TosUri.String,
		PolicyURI:                    row.PolicyUri.String,
		JWKsURI:                      row.JwksUri.String,
		SoftwareID:                   row.SoftwareID.String,
		SoftwareVersion:              row.SoftwareVersion.String,
		SubjectType:                  string(row.SubjectType.ClientSubjectType),
		SectorIdentifierURI:          row.SectorIdentifierUri.String,
		DefaultMaxAge:                int64(row.DefaultMaxAge.Int32),
		RequireAuthTime:              row.RequireAuthTime,
		DefaultACRValues:             row.DefaultAcrValues,
		InitiateLoginURI:             row.InitiateLoginUri.String,
		RequestURIs:                  row.RequestUris,
		IDTokenSignedResponseAlg:     string(row.IDTokenSignedResponseAlg),
		IDTokenEncryptedResponseAlg:  string(row.IDTokenEncryptedResponseAlg.TokenEncryptionAlgorithm),
		IDTokenEncryptedResponseEnc:  string(row.IDTokenEncryptedResponseEnc.TokenEncryptionEncoding),
		UserInfoSignedResponseAlg:    string(row.UserinfoSignedResponseAlg.TokenCryptoSuite),
		UserInfoEncryptedResponseAlg: string(row.UserinfoEncryptedResponseAlg.TokenEncryptionAlgorithm),
		UserInfoEncryptedResponseEnc: string(row.UserinfoEncryptedResponseEnc.TokenEncryptionEncoding),
		RequestObjectSigningAlg:      string(row.RequestObjectSigningAlg.TokenCryptoSuite),
		RequestObjectEncryptionAlg:   string(row.RequestObjectEncryptionAlg.TokenEncryptionAlgorithm),
		RequestObjectEncryptionEnc:   string(row.RequestObjectEncryptionEnc.TokenEncryptionEncoding),
		TokenEndpointAuthSigningAlg:  string(row.TokenEndpointAuthSigningAlg.TokenCryptoSuite),
		AccessTokenSigningAlg:        string(row.AccessTokenSigningAlg),
	}
	if len(row.Jwks) > 0 {
		var set utils.JWKSet
		if json.Unmarshal(row.Jwks, &set) == nil {
			metadata.JWKs = &set
		}
	}
	result := &ClientRegistrationDTO{SoftwareStatementClaims: metadata, ClientID: row.ClientID, ClientIDIssuedAt: row.CreatedAt.Unix(), SoftwareStatement: statement, ClientSecret: secret, ClientSecretJWK: key}
	if secret != "" {
		var exp int64
		if !expiry.IsZero() {
			exp = expiry.Unix()
		}
		result.ClientSecretExpiresAt = &exp
	}
	return result
}

func registrationFromAccountCredential(row *database.AccountCredential, statement, secret string, expiry time.Time, key utils.JWK) *ClientRegistrationDTO {
	metadata := tokens.SoftwareStatementClaims{
		RedirectURIs:                 row.RedirectUris,
		TokenEndpointAuthMethod:      string(row.TokenEndpointAuthMethod),
		GrantTypes:                   utils.MapSlice(row.GrantTypes, func(v *database.GrantType) string { return string(*v) }),
		ResponseTypes:                utils.MapSlice(row.ResponseTypes, func(v *database.ResponseType) string { return string(*v) }),
		ApplicationType:              string(row.CredentialsType),
		ClientName:                   row.ClientName,
		ClientURI:                    row.ClientUri,
		LogoURI:                      row.LogoUri.String,
		Scope:                        strings.Join(utils.MapSlice(row.Scopes, func(s *database.AccountCredentialsScope) string { return string(*s) }), " "),
		Contacts:                     row.Contacts,
		TOSURI:                       row.TosUri.String,
		PolicyURI:                    row.PolicyUri.String,
		JWKsURI:                      row.JwksUri.String,
		SoftwareID:                   row.SoftwareID.String,
		SoftwareVersion:              row.SoftwareVersion.String,
		SubjectType:                  string(row.SubjectType.ClientSubjectType),
		SectorIdentifierURI:          row.SectorIdentifierUri.String,
		DefaultMaxAge:                int64(row.DefaultMaxAge.Int64),
		RequireAuthTime:              row.RequireAuthTime,
		DefaultACRValues:             row.DefaultAcrValues,
		InitiateLoginURI:             row.InitiateLoginUri.String,
		RequestURIs:                  row.RequestUris,
		IDTokenSignedResponseAlg:     string(row.IDTokenSignedResponseAlg),
		IDTokenEncryptedResponseAlg:  string(row.IDTokenEncryptedResponseAlg.TokenEncryptionAlgorithm),
		IDTokenEncryptedResponseEnc:  string(row.IDTokenEncryptedResponseEnc.TokenEncryptionEncoding),
		UserInfoSignedResponseAlg:    string(row.UserinfoSignedResponseAlg.TokenCryptoSuite),
		UserInfoEncryptedResponseAlg: string(row.UserinfoEncryptedResponseAlg.TokenEncryptionAlgorithm),
		UserInfoEncryptedResponseEnc: string(row.UserinfoEncryptedResponseEnc.TokenEncryptionEncoding),
		RequestObjectSigningAlg:      string(row.RequestObjectSigningAlg.TokenCryptoSuite),
		RequestObjectEncryptionAlg:   string(row.RequestObjectEncryptionAlg.TokenEncryptionAlgorithm),
		RequestObjectEncryptionEnc:   string(row.RequestObjectEncryptionEnc.TokenEncryptionEncoding),
		TokenEndpointAuthSigningAlg:  string(row.TokenEndpointAuthSigningAlg.TokenCryptoSuite),
		AccessTokenSigningAlg:        string(row.AccessTokenSigningAlg),
	}
	if len(row.Jwks) > 0 {
		var set utils.JWKSet
		if json.Unmarshal(row.Jwks, &set) == nil {
			metadata.JWKs = &set
		}
	}
	result := &ClientRegistrationDTO{SoftwareStatementClaims: metadata, ClientID: row.ClientID, ClientIDIssuedAt: row.CreatedAt.Unix(), SoftwareStatement: statement, ClientSecret: secret, ClientSecretJWK: key}
	if secret != "" {
		var exp int64
		if !expiry.IsZero() {
			exp = expiry.Unix()
		}
		result.ClientSecretExpiresAt = &exp
	}
	return result
}

func MapRegisteredApp(row *database.App, statement, secret string, expiry time.Time, key utils.JWK) AppDTO {
	dto := MapAppToDTO(row)
	dto.ClientSecret = secret
	dto.ClientSecretJWK = key
	if !expiry.IsZero() {
		dto.ClientSecretExp = expiry.Unix()
	}
	dto.Registration = registrationFromApp(row, statement, secret, expiry, key)
	return dto
}

func MapRegisteredAccountCredentials(row *database.AccountCredential, statement, secret string, expiry time.Time, key utils.JWK) (AccountCredentialsDTO, *exceptions.ServiceError) {
	dto, err := MapAccountCredentialsToDTO(row)
	if err != nil {
		return dto, err
	}
	dto.ClientSecret = secret
	dto.ClientSecretJWK = key
	if !expiry.IsZero() {
		dto.ClientSecretExp = expiry.Unix()
	}
	dto.Registration = registrationFromAccountCredential(row, statement, secret, expiry, key)
	return dto, nil
}
