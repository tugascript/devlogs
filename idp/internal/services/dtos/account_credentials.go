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

	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type AccountCredentialsDTO struct {
	ClientID                string                             `json:"client_id"`
	Type                    database.AccountCredentialsType    `json:"type"`
	Name                    string                             `json:"name"`
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
	ClientSecretID          string                             `json:"client_secret_id,omitempty"`
	ClientSecret            string                             `json:"client_secret,omitempty"`
	ClientSecretJWK         utils.JWK                          `json:"client_secret_jwk,omitempty"`
	ClientSecretExp         int64                              `json:"client_secret_exp,omitempty"`

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
		ClientSecretJWK json.RawMessage `json:"client_secret_jwk"`
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

	return nil
}

func MapAccountCredentialsToDTO(
	accountCredential *database.AccountCredential,
) AccountCredentialsDTO {
	var redirectURIs []string
	if len(accountCredential.RedirectUris) > 0 {
		redirectURIs = accountCredential.RedirectUris
	}

	var contacts []string
	if len(accountCredential.Contacts) > 0 {
		contacts = accountCredential.Contacts
	}

	return AccountCredentialsDTO{
		id:                      accountCredential.ID,
		ClientID:                accountCredential.ClientID,
		Type:                    accountCredential.CredentialsType,
		Name:                    accountCredential.Name,
		Domain:                  accountCredential.Domain,
		ClientURI:               accountCredential.ClientUri,
		RedirectURIs:            redirectURIs,
		LogoURI:                 accountCredential.LogoUri.String,
		TOSURI:                  accountCredential.TosUri.String,
		PolicyURI:               accountCredential.PolicyUri.String,
		SoftwareID:              accountCredential.SoftwareID,
		SoftwareVersion:         accountCredential.SoftwareVersion.String,
		Contacts:                contacts,
		CreationMethod:          accountCredential.CreationMethod,
		Transport:               accountCredential.Transport,
		TokenEndpointAuthMethod: accountCredential.TokenEndpointAuthMethod,
		accountId:               accountCredential.AccountID,
	}
}

func MapAccountCredentialsToDTOWithJWK(
	accountKeys *database.AccountCredential,
	jwk utils.JWK,
	exp time.Time,
) AccountCredentialsDTO {
	var contacts []string
	if len(accountKeys.Contacts) > 0 {
		contacts = accountKeys.Contacts
	}

	return AccountCredentialsDTO{
		id:                      accountKeys.ID,
		Type:                    accountKeys.CredentialsType,
		Name:                    accountKeys.Name,
		Domain:                  accountKeys.Domain,
		ClientURI:               accountKeys.ClientUri,
		RedirectURIs:            accountKeys.RedirectUris,
		LogoURI:                 accountKeys.LogoUri.String,
		TOSURI:                  accountKeys.TosUri.String,
		PolicyURI:               accountKeys.PolicyUri.String,
		SoftwareID:              accountKeys.SoftwareID,
		SoftwareVersion:         accountKeys.SoftwareVersion.String,
		Contacts:                contacts,
		CreationMethod:          accountKeys.CreationMethod,
		Transport:               accountKeys.Transport,
		TokenEndpointAuthMethod: accountKeys.TokenEndpointAuthMethod,
		accountId:               accountKeys.AccountID,
		ClientID:                accountKeys.ClientID,
		ClientSecretID:          jwk.GetKeyID(),
		ClientSecretJWK:         jwk,
		ClientSecretExp:         exp.Unix(),
		Scopes:                  accountKeys.Scopes,
	}
}

func MapAccountCredentialsToDTOWithSecret(
	accountKeys *database.AccountCredential,
	secretID,
	secret string,
	exp time.Time,
) AccountCredentialsDTO {
	var contacts []string
	if len(accountKeys.Contacts) > 0 {
		contacts = accountKeys.Contacts
	}

	return AccountCredentialsDTO{
		id:                      accountKeys.ID,
		Type:                    accountKeys.CredentialsType,
		Name:                    accountKeys.Name,
		Domain:                  accountKeys.Domain,
		ClientURI:               accountKeys.ClientUri,
		RedirectURIs:            accountKeys.RedirectUris,
		LogoURI:                 accountKeys.LogoUri.String,
		TOSURI:                  accountKeys.TosUri.String,
		PolicyURI:               accountKeys.PolicyUri.String,
		SoftwareID:              accountKeys.SoftwareID,
		SoftwareVersion:         accountKeys.SoftwareVersion.String,
		Contacts:                contacts,
		CreationMethod:          accountKeys.CreationMethod,
		Transport:               accountKeys.Transport,
		TokenEndpointAuthMethod: accountKeys.TokenEndpointAuthMethod,
		accountId:               accountKeys.AccountID,
		ClientID:                accountKeys.ClientID,
		ClientSecretID:          secretID,
		ClientSecret:            fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp:         exp.Unix(),
		Scopes:                  accountKeys.Scopes,
	}
}
