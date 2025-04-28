// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type OAuthProviderConfig struct {
	clientID     string
	clientSecret string
	enabled      bool
}

func NewOAuthProvider(clientID, clientSecret string) OAuthProviderConfig {
	if clientID == "" || clientSecret == "" {
		return OAuthProviderConfig{enabled: false}
	}

	return OAuthProviderConfig{
		clientID:     clientID,
		clientSecret: clientSecret,
		enabled:      true,
	}
}

func (o *OAuthProviderConfig) ClientID() string {
	return o.clientID
}

func (o *OAuthProviderConfig) ClientSecret() string {
	return o.clientSecret
}

func (o *OAuthProviderConfig) Enabled() bool {
	return o.enabled
}

type OAuthProvidersConfig struct {
	gitHub    OAuthProviderConfig
	google    OAuthProviderConfig
	facebook  OAuthProviderConfig
	apple     OAuthProviderConfig
	microsoft OAuthProviderConfig
}

func NewOAuthProviders(gitHub, google, facebook, apple, microsoft OAuthProviderConfig) OAuthProvidersConfig {
	return OAuthProvidersConfig{
		gitHub:    gitHub,
		google:    google,
		facebook:  facebook,
		apple:     apple,
		microsoft: microsoft,
	}
}

func (o *OAuthProvidersConfig) GitHub() OAuthProviderConfig {
	return o.gitHub
}

func (o *OAuthProvidersConfig) Google() OAuthProviderConfig {
	return o.google
}

func (o *OAuthProvidersConfig) Facebook() OAuthProviderConfig {
	return o.facebook
}

func (o *OAuthProvidersConfig) Apple() OAuthProviderConfig {
	return o.apple
}

func (o *OAuthProvidersConfig) Microsoft() OAuthProviderConfig {
	return o.microsoft
}
