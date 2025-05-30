// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/utils"
)

const (
	AuthProviderEmail            string = "email"
	AuthProviderGoogle           string = "google"
	AuthProviderGitHub           string = "github"
	AuthProviderApple            string = "apple"
	AuthProviderMicrosoft        string = "microsoft"
	AuthProviderFacebook         string = "facebook"
	AuthProviderUsernamePassword string = "username_password"

	TwoFactorNone  string = "none"
	TwoFactorEmail string = "email"
	TwoFactorTotp  string = "totp"

	UsernameColumnEmail    string = "email"
	UsernameColumnUsername string = "username"
	UsernameColumnBoth     string = "both"
)

func (s *Services) buildLogger(requestID, location, function string) *slog.Logger {
	return utils.BuildLogger(s.logger, utils.LoggerOptions{
		Layer:     utils.ServicesLogLayer,
		Location:  location,
		Method:    function,
		RequestID: requestID,
	})
}
