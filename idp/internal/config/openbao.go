// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package config

type OpenBaoConfig struct {
	urlAddress string
	devToken   string
	roleID     string
	secretID   string
}

func NewOpenBaoConfig(urlAddress, devToken, roleID, secretID string) OpenBaoConfig {
	return OpenBaoConfig{
		urlAddress: urlAddress,
		devToken:   devToken,
		roleID:     roleID,
		secretID:   secretID,
	}
}

func (c *OpenBaoConfig) URLAddress() string {
	return c.urlAddress
}

func (c *OpenBaoConfig) DevToken() string {
	return c.devToken
}

func (c *OpenBaoConfig) RoleID() string {
	return c.roleID
}

func (c *OpenBaoConfig) SecretID() string {
	return c.secretID
}
