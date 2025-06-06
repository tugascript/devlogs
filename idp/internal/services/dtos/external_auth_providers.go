// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package dtos

import (
	"encoding/json"
	"github.com/tugascript/devlogs/idp/internal/exceptions"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
)

type ExternalAuthProviderDTO struct {
	encryptedClientSecret string

	ID           int32             `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	Icon         string            `json:"icon"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret,omitempty"`
	Scopes       []string          `json:"scopes"`
	AuthURL      string            `json:"auth_url"`
	TokenURL     string            `json:"token_url"`
	UserInfoURL  string            `json:"user_info_url"`
	EmailKey     string            `json:"email_key"`
	UserSchema   SchemaDTO         `json:"user_schema"`
	UserMapping  map[string]string `json:"user_mapping"`
}

func (eap *ExternalAuthProviderDTO) EncryptClientSecret() string {
	return eap.encryptedClientSecret
}

func MapExternalAuthProviderToDTO(
	authProvider *database.ExternalAuthProvider,
) (ExternalAuthProviderDTO, *exceptions.ServiceError) {
	schema := make(SchemaDTO)
	if err := json.Unmarshal(authProvider.UserSchema, &schema); err != nil {
		return ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	mapping := make(map[string]string)
	if err := json.Unmarshal(authProvider.UserMapping, &mapping); err != nil {
		return ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	return ExternalAuthProviderDTO{
		ID:                    authProvider.ID,
		Name:                  authProvider.Name,
		Provider:              authProvider.Provider,
		Icon:                  authProvider.Icon,
		ClientID:              authProvider.ClientID,
		Scopes:                authProvider.Scopes,
		AuthURL:               authProvider.AuthUrl,
		TokenURL:              authProvider.TokenUrl,
		UserInfoURL:           authProvider.UserInfoUrl,
		EmailKey:              authProvider.EmailKey,
		UserSchema:            schema,
		UserMapping:           mapping,
		encryptedClientSecret: authProvider.ClientSecret,
	}, nil
}

func MapExternalAuthProviderWithSecretToDTO(
	authProvider *database.ExternalAuthProvider,
	clientSecret string,
) (ExternalAuthProviderDTO, *exceptions.ServiceError) {
	schema := make(SchemaDTO)
	if err := json.Unmarshal(authProvider.UserSchema, &schema); err != nil {
		return ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	mapping := make(map[string]string)
	if err := json.Unmarshal(authProvider.UserMapping, &mapping); err != nil {
		return ExternalAuthProviderDTO{}, exceptions.NewServerError()
	}

	return ExternalAuthProviderDTO{
		ID:                    authProvider.ID,
		Name:                  authProvider.Name,
		Provider:              authProvider.Provider,
		Icon:                  authProvider.Icon,
		ClientID:              authProvider.ClientID,
		ClientSecret:          clientSecret,
		Scopes:                authProvider.Scopes,
		AuthURL:               authProvider.AuthUrl,
		TokenURL:              authProvider.TokenUrl,
		UserInfoURL:           authProvider.UserInfoUrl,
		EmailKey:              authProvider.EmailKey,
		UserSchema:            schema,
		UserMapping:           mapping,
		encryptedClientSecret: authProvider.ClientSecret,
	}, nil
}
