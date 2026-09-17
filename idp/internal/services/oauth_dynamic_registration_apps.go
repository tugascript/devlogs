// Copyright (c) 2026 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"context"

	"github.com/tugascript/devlogs/idp/internal/exceptions"
)

const oauthDynamicRegistrationAppsLocation string = "oauth_dynamic_registration_apps"

type InitiateAppsOAuthDynamicRegistrationIATAuthOptions struct {
	RequestID       string
	Origin          string
	Domain          string
	State           string
	SessionKey      string
	RefreshToken    string
	Challenge       string
	ChallengeMethod string
	RedirectURI     string
	BackendDomain   string
	Hostname        string
}

func (s *Services) InitiateAppsOAuthDynamicRegistrationIATAuth(
	ctx context.Context,
	opts InitiateAppsOAuthDynamicRegistrationIATAuthOptions,
) (string, *exceptions.ServiceError) {
	logger := s.buildLogger(
		opts.RequestID,
		oauthDynamicRegistrationAppsLocation,
		"InitiateAppsOAuthDynamicRegistrationIATAuth",
	).With("hostname", opts.Hostname)
	logger.InfoContext(ctx, "Starting OAuth dynamic registration IAT authorization for Apps...")

	if serviceErr := validateOrigin(ctx, logger, opts.Origin, opts.Domain); serviceErr != nil {
		return "", serviceErr
	}

	return "", nil
}
