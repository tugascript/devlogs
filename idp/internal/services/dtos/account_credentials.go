// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AccountCredentialsDTO struct {
	ClientID                string                             `json:"client_id"`
	Type                    database.AccountCredentialsType    `json:"application_type"`
	ClientName              string                             `json:"client_name"`
	Domain                  string                             `json:"domain"`
	Scopes                  []database.AccountCredentialsScope `json:"scopes"`
	TokenEndpointAuthMethod database.AuthMethod                `json:"token_endpoint_auth_method"`
	Transport               database.Transport                 `json:"transport"`
	CreationMethod          database.CreationMethod            `json:"creation_method"`
	ClientURI               string                             `json:"client_uri"`
	RedirectURIs            []string                           `json:"redirect_uris"`
	LogoURI                 string                             `json:"logo_uri,omitempty"`
	TOSURI                  string                             `json:"tos_uri,omitempty"`
	PolicyURI               string                             `json:"policy_uri,omitempty"`
	SoftwareID              string                             `json:"software_id"`
	SoftwareVersion         string                             `json:"software_version,omitempty"`
	Contacts                []string                           `json:"contacts,omitempty"`
	JWKsURI                 string                             `json:"jwks_uri,omitempty"`
	JWKs                    []utils.JWK                        `json:"jwks,omitempty"`

	SectorIdentifierURI          string                            `json:"sector_identifier_uri,omitempty"`
	SubjectType                  database.ClientSubjectType        `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     database.TokenCryptoSuite         `json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg  database.TokenEncryptionAlgorithm `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  database.TokenEncryptionEncoding  `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoSignedResponseAlg    database.TokenCryptoSuite         `json:"userinfo_signed_response_alg,omitempty"`
	UserInfoEncryptedResponseAlg database.TokenEncryptionAlgorithm `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc database.TokenEncryptionEncoding  `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      database.TokenCryptoSuite         `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   database.TokenEncryptionAlgorithm `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   database.TokenEncryptionEncoding  `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthSigningAlg  database.TokenCryptoSuite         `json:"token_endpoint_auth_signing_alg,omitempty"`
	AccessTokenSigningAlg        database.TokenCryptoSuite         `json:"access_token_signing_alg"`
	DefaultMaxAge                int64                             `json:"default_max_age,omitempty"`
	RequireAuthTime              bool                              `json:"require_auth_time,omitempty"`
	DefaultACRValues             []string                          `json:"default_acr_values,omitempty"`
	InitiateLoginURI             string                            `json:"initiate_login_uri,omitempty"`
	RequestURIs                  []string                          `json:"request_uris,omitempty"`

	ClientSecretID  string    `json:"client_secret_id,omitempty"`
	ClientSecret    string    `json:"client_secret,omitempty"`
	ClientSecretJWK utils.JWK `json:"client_secret_jwk,omitempty"`
	ClientSecretExp int64     `json:"client_secret_exp,omitempty"`

	id        int32
	accountId int32
}

func (ak *AccountCredentialsDTO) AccountID() int32 {
	return ak.accountId
}

func (ak *AccountCredentialsDTO) ID() int32 {
	return ak.id
}

func (ak *AccountCredentialsDTO) UnmarshalJSON(data []byte) error {
	type Alias AccountCredentialsDTO
	aux := &struct {
		ClientSecretJWK json.RawMessage   `json:"client_secret_jwk"`
		JWKs            []json.RawMessage `json:"jwks"`
		*Alias
	}{
		Alias: (*Alias)(ak),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.ClientSecretJWK != nil {
		jwk, err := utils.JsonToJWK(aux.ClientSecretJWK)
		if err != nil {
			return err
		}
		ak.ClientSecretJWK = jwk
	}

	if aux.JWKs != nil {
		jwks := make([]utils.JWK, 0, len(aux.JWKs))
		for _, raw := range aux.JWKs {
			jwk, err := utils.JsonToJWK(raw)
			if err != nil {
				return err
			}
			jwks = append(jwks, jwk)
		}
		ak.JWKs = jwks
	}

	return nil
}

func MapAccountCredentialsToDTO(
	accountCredential *database.AccountCredential,
) (AccountCredentialsDTO, *exceptions.ServiceError) {
	var redirectURIs []string
	if len(accountCredential.RedirectUris) > 0 {
		redirectURIs = accountCredential.RedirectUris
	}

	var contacts []string
	if len(accountCredential.Contacts) > 0 {
		contacts = accountCredential.Contacts
	}

	jwks := make([]utils.JWK, 0)
	if accountCredential.Jwks != nil {
		var rawJwks []json.RawMessage
		if err := json.Unmarshal(accountCredential.Jwks, &rawJwks); err != nil {
			return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
		}
		for _, raw := range rawJwks {
			jwk, err := utils.JsonToJWK(raw)
			if err != nil {
				return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
			}
			jwks = append(jwks, jwk)
		}
	}

	return AccountCredentialsDTO{
		id:                           accountCredential.ID,
		ClientID:                     accountCredential.ClientID,
		Type:                         accountCredential.CredentialsType,
		ClientName:                   accountCredential.ClientName,
		Domain:                       accountCredential.Domain,
		ClientURI:                    accountCredential.ClientUri,
		RedirectURIs:                 redirectURIs,
		LogoURI:                      accountCredential.LogoUri.String,
		TOSURI:                       accountCredential.TosUri.String,
		PolicyURI:                    accountCredential.PolicyUri.String,
		SoftwareID:                   accountCredential.SoftwareID.String,
		SoftwareVersion:              accountCredential.SoftwareVersion.String,
		Contacts:                     contacts,
		CreationMethod:               accountCredential.CreationMethod,
		Transport:                    accountCredential.Transport,
		TokenEndpointAuthMethod:      accountCredential.TokenEndpointAuthMethod,
		accountId:                    accountCredential.AccountID,
		JWKsURI:                      accountCredential.JwksUri.String,
		JWKs:                         jwks,
		SectorIdentifierURI:          accountCredential.SectorIdentifierUri.String,
		SubjectType:                  accountCredential.SubjectType.ClientSubjectType,
		IDTokenSignedResponseAlg:     accountCredential.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  accountCredential.IDTokenEncryptedResponseAlg.TokenEncryptionAlgorithm,
		IDTokenEncryptedResponseEnc:  accountCredential.IDTokenEncryptedResponseEnc.TokenEncryptionEncoding,
		UserInfoSignedResponseAlg:    accountCredential.UserinfoSignedResponseAlg.TokenCryptoSuite,
		UserInfoEncryptedResponseAlg: accountCredential.UserinfoEncryptedResponseAlg.TokenEncryptionAlgorithm,
		UserInfoEncryptedResponseEnc: accountCredential.UserinfoEncryptedResponseEnc.TokenEncryptionEncoding,
		RequestObjectSigningAlg:      accountCredential.RequestObjectSigningAlg.TokenCryptoSuite,
		RequestObjectEncryptionAlg:   accountCredential.RequestObjectEncryptionAlg.TokenEncryptionAlgorithm,
		RequestObjectEncryptionEnc:   accountCredential.RequestObjectEncryptionEnc.TokenEncryptionEncoding,
		TokenEndpointAuthSigningAlg:  accountCredential.TokenEndpointAuthSigningAlg.TokenCryptoSuite,
		AccessTokenSigningAlg:        accountCredential.AccessTokenSigningAlg,
		DefaultMaxAge:                accountCredential.DefaultMaxAge.Int64,
		RequireAuthTime:              accountCredential.RequireAuthTime,
		DefaultACRValues:             accountCredential.DefaultAcrValues,
		InitiateLoginURI:             accountCredential.InitiateLoginUri.String,
		RequestURIs:                  accountCredential.RequestUris,
	}, nil
}

func MapAccountCredentialsToDTOWithJWK(
	accountCredential *database.AccountCredential,
	jwk utils.JWK,
	exp time.Time,
) (AccountCredentialsDTO, *exceptions.ServiceError) {
	var contacts []string
	if len(accountCredential.Contacts) > 0 {
		contacts = accountCredential.Contacts
	}

	jwks := make([]utils.JWK, 0)
	if accountCredential.Jwks != nil {
		var rawJwks []json.RawMessage
		if err := json.Unmarshal(accountCredential.Jwks, &rawJwks); err != nil {
			return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
		}
		for _, raw := range rawJwks {
			jwk, err := utils.JsonToJWK(raw)
			if err != nil {
				return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
			}
			jwks = append(jwks, jwk)
		}
	}

	return AccountCredentialsDTO{
		id:                           accountCredential.ID,
		Type:                         accountCredential.CredentialsType,
		ClientName:                   accountCredential.ClientName,
		Domain:                       accountCredential.Domain,
		ClientURI:                    accountCredential.ClientUri,
		RedirectURIs:                 accountCredential.RedirectUris,
		LogoURI:                      accountCredential.LogoUri.String,
		TOSURI:                       accountCredential.TosUri.String,
		PolicyURI:                    accountCredential.PolicyUri.String,
		SoftwareID:                   accountCredential.SoftwareID.String,
		SoftwareVersion:              accountCredential.SoftwareVersion.String,
		Contacts:                     contacts,
		CreationMethod:               accountCredential.CreationMethod,
		Transport:                    accountCredential.Transport,
		TokenEndpointAuthMethod:      accountCredential.TokenEndpointAuthMethod,
		accountId:                    accountCredential.AccountID,
		ClientID:                     accountCredential.ClientID,
		ClientSecretID:               jwk.GetKeyID(),
		ClientSecretJWK:              jwk,
		ClientSecretExp:              exp.Unix(),
		Scopes:                       accountCredential.Scopes,
		JWKsURI:                      accountCredential.JwksUri.String,
		JWKs:                         jwks,
		SectorIdentifierURI:          accountCredential.SectorIdentifierUri.String,
		SubjectType:                  accountCredential.SubjectType.ClientSubjectType,
		IDTokenSignedResponseAlg:     accountCredential.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  accountCredential.IDTokenEncryptedResponseAlg.TokenEncryptionAlgorithm,
		IDTokenEncryptedResponseEnc:  accountCredential.IDTokenEncryptedResponseEnc.TokenEncryptionEncoding,
		UserInfoSignedResponseAlg:    accountCredential.UserinfoSignedResponseAlg.TokenCryptoSuite,
		UserInfoEncryptedResponseAlg: accountCredential.UserinfoEncryptedResponseAlg.TokenEncryptionAlgorithm,
		UserInfoEncryptedResponseEnc: accountCredential.UserinfoEncryptedResponseEnc.TokenEncryptionEncoding,
		RequestObjectSigningAlg:      accountCredential.RequestObjectSigningAlg.TokenCryptoSuite,
		RequestObjectEncryptionAlg:   accountCredential.RequestObjectEncryptionAlg.TokenEncryptionAlgorithm,
		RequestObjectEncryptionEnc:   accountCredential.RequestObjectEncryptionEnc.TokenEncryptionEncoding,
		TokenEndpointAuthSigningAlg:  accountCredential.TokenEndpointAuthSigningAlg.TokenCryptoSuite,
		AccessTokenSigningAlg:        accountCredential.AccessTokenSigningAlg,
		DefaultMaxAge:                accountCredential.DefaultMaxAge.Int64,
		RequireAuthTime:              accountCredential.RequireAuthTime,
		DefaultACRValues:             accountCredential.DefaultAcrValues,
		InitiateLoginURI:             accountCredential.InitiateLoginUri.String,
		RequestURIs:                  accountCredential.RequestUris,
	}, nil
}

func MapAccountCredentialsToDTOWithSecret(
	accountCredential *database.AccountCredential,
	secretID,
	secret string,
	exp time.Time,
) (AccountCredentialsDTO, *exceptions.ServiceError) {
	var contacts []string
	if len(accountCredential.Contacts) > 0 {
		contacts = accountCredential.Contacts
	}

	jwks := make([]utils.JWK, 0)
	if accountCredential.Jwks != nil {
		var rawJwks []json.RawMessage
		if err := json.Unmarshal(accountCredential.Jwks, &rawJwks); err != nil {
			return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
		}
		for _, raw := range rawJwks {
			jwk, err := utils.JsonToJWK(raw)
			if err != nil {
				return AccountCredentialsDTO{}, exceptions.NewInternalServerError()
			}
			jwks = append(jwks, jwk)
		}
	}

	return AccountCredentialsDTO{
		id:                           accountCredential.ID,
		Type:                         accountCredential.CredentialsType,
		ClientName:                   accountCredential.ClientName,
		Domain:                       accountCredential.Domain,
		ClientURI:                    accountCredential.ClientUri,
		RedirectURIs:                 accountCredential.RedirectUris,
		LogoURI:                      accountCredential.LogoUri.String,
		TOSURI:                       accountCredential.TosUri.String,
		PolicyURI:                    accountCredential.PolicyUri.String,
		SoftwareID:                   accountCredential.SoftwareID.String,
		SoftwareVersion:              accountCredential.SoftwareVersion.String,
		Contacts:                     contacts,
		CreationMethod:               accountCredential.CreationMethod,
		Transport:                    accountCredential.Transport,
		TokenEndpointAuthMethod:      accountCredential.TokenEndpointAuthMethod,
		accountId:                    accountCredential.AccountID,
		ClientID:                     accountCredential.ClientID,
		ClientSecretID:               secretID,
		ClientSecret:                 fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp:              exp.Unix(),
		Scopes:                       accountCredential.Scopes,
		JWKsURI:                      accountCredential.JwksUri.String,
		JWKs:                         jwks,
		SectorIdentifierURI:          accountCredential.SectorIdentifierUri.String,
		SubjectType:                  accountCredential.SubjectType.ClientSubjectType,
		IDTokenSignedResponseAlg:     accountCredential.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  accountCredential.IDTokenEncryptedResponseAlg.TokenEncryptionAlgorithm,
		IDTokenEncryptedResponseEnc:  accountCredential.IDTokenEncryptedResponseEnc.TokenEncryptionEncoding,
		UserInfoSignedResponseAlg:    accountCredential.UserinfoSignedResponseAlg.TokenCryptoSuite,
		UserInfoEncryptedResponseAlg: accountCredential.UserinfoEncryptedResponseAlg.TokenEncryptionAlgorithm,
		UserInfoEncryptedResponseEnc: accountCredential.UserinfoEncryptedResponseEnc.TokenEncryptionEncoding,
		RequestObjectSigningAlg:      accountCredential.RequestObjectSigningAlg.TokenCryptoSuite,
		RequestObjectEncryptionAlg:   accountCredential.RequestObjectEncryptionAlg.TokenEncryptionAlgorithm,
		RequestObjectEncryptionEnc:   accountCredential.RequestObjectEncryptionEnc.TokenEncryptionEncoding,
		TokenEndpointAuthSigningAlg:  accountCredential.TokenEndpointAuthSigningAlg.TokenCryptoSuite,
		AccessTokenSigningAlg:        accountCredential.AccessTokenSigningAlg,
		DefaultMaxAge:                accountCredential.DefaultMaxAge.Int64,
		RequireAuthTime:              accountCredential.RequireAuthTime,
		DefaultACRValues:             accountCredential.DefaultAcrValues,
		InitiateLoginURI:             accountCredential.InitiateLoginUri.String,
		RequestURIs:                  accountCredential.RequestUris,
	}, nil
}
