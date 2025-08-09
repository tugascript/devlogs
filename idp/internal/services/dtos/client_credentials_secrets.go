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

const (
	ClientCredentialSecretStatusActive  string = "active"
	ClientCredentialSecretStatusExpired string = "expired"
	ClientCredentialSecretStatusRevoked string = "revoked"

	ClientCredentialSecretTypeJWK    string = "jwk"
	ClientCredentialSecretTypeSecret string = "secret"
)

type ClientCredentialsSecretDTO struct {
	id int32

	PublicID              string    `json:"id"`
	ClientSecret          string    `json:"client_secret,omitempty"`
	ClientSecretJWK       utils.JWK `json:"client_secret_jwk,omitempty"`
	ClientSecretPublicJWK utils.JWK `json:"client_secret_public_jwk,omitempty"`
	ClientSecretExp       int64     `json:"client_secret_exp"`
	Status                string    `json:"status"`
	Type                  string    `json:"type"`
}

func (s *ClientCredentialsSecretDTO) UnmarshalJSON(data []byte) error {
	type Alias ClientCredentialsSecretDTO
	aux := &struct {
		ClientSecretJWK       json.RawMessage `json:"client_secret_jwk"`
		ClientSecretPublicJWK json.RawMessage `json:"client_secret_public_jwk,omitempty"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	if aux.ClientSecretJWK != nil {
		jwk, err := utils.JsonToJWK(aux.ClientSecretJWK)
		if err != nil {
			return err
		}
		s.ClientSecretJWK = jwk
	}
	if aux.ClientSecretPublicJWK != nil {
		jwk, err := utils.JsonToJWK(aux.ClientSecretPublicJWK)
		if err != nil {
			return err
		}
		s.ClientSecretPublicJWK = jwk
	}

	return nil
}

func (s *ClientCredentialsSecretDTO) ID() int32 {
	return s.id
}

func getCredentialsSecretStatus(secret *database.CredentialsSecret) string {
	if secret.IsRevoked {
		return ClientCredentialSecretStatusRevoked
	}
	if secret.ExpiresAt.Before(time.Now()) {
		return ClientCredentialSecretStatusExpired
	}
	return ClientCredentialSecretStatusActive
}

func MapCredentialsSecretToDTO(
	secret *database.CredentialsSecret,
) ClientCredentialsSecretDTO {
	return ClientCredentialsSecretDTO{
		id:       secret.ID,
		PublicID: secret.SecretID,
		Type:     ClientCredentialSecretTypeSecret,
		Status:   getCredentialsSecretStatus(secret),
	}
}

func CreateCredentialsSecretToDTOWithSecret(
	id int32,
	secretID string,
	secret string,
	exp time.Time,
) ClientCredentialsSecretDTO {
	return ClientCredentialsSecretDTO{
		id:              id,
		PublicID:        secretID,
		Type:            ClientCredentialSecretTypeSecret,
		Status:          ClientCredentialSecretStatusActive,
		ClientSecret:    fmt.Sprintf("%s.%s", secretID, secret),
		ClientSecretExp: exp.Unix(),
	}
}

func getCredentialsKeyStatus(key *database.CredentialsKey) string {
	if key.IsRevoked {
		return ClientCredentialSecretStatusRevoked
	}
	if key.ExpiresAt.Before(time.Now()) {
		return ClientCredentialSecretStatusExpired
	}
	return ClientCredentialSecretStatusActive
}

func MapCredentialsKeyToDTO(
	key *database.CredentialsKey,
) (ClientCredentialsSecretDTO, *exceptions.ServiceError) {
	jwk, err := utils.JsonToJWK(key.PublicKey)
	if err != nil {
		return ClientCredentialsSecretDTO{}, exceptions.NewInternalServerError()
	}

	return ClientCredentialsSecretDTO{
		id:                    key.ID,
		PublicID:              key.PublicKid,
		Type:                  ClientCredentialSecretTypeJWK,
		Status:                getCredentialsKeyStatus(key),
		ClientSecretPublicJWK: jwk,
		ClientSecretExp:       key.ExpiresAt.Unix(),
	}, nil
}

func MapCredentialsKeyToDTOWithJWK(
	key *database.CredentialsKey,
	jwk utils.JWK,
) ClientCredentialsSecretDTO {
	return ClientCredentialsSecretDTO{
		id:              key.ID,
		PublicID:        key.PublicKid,
		Type:            ClientCredentialSecretTypeJWK,
		Status:          getCredentialsKeyStatus(key),
		ClientSecretJWK: jwk,
		ClientSecretExp: key.ExpiresAt.Unix(),
	}
}
