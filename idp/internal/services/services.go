// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/encryption"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
)

type Services struct {
	logger         *slog.Logger
	database       *database.Database
	cache          *cache.Cache
	mail           *mailer.EmailPublisher
	jwt            *tokens.Tokens
	encrypt        *encryption.Encryption
	oauthProviders *oauth.Providers
}

func NewServices(
	logger *slog.Logger,
	database *database.Database,
	cache *cache.Cache,
	mail *mailer.EmailPublisher,
	jwt *tokens.Tokens,
	encrypt *encryption.Encryption,
	oauthProv *oauth.Providers,
) *Services {
	return &Services{
		logger:         logger,
		database:       database,
		cache:          cache,
		mail:           mail,
		jwt:            jwt,
		encrypt:        encrypt,
		oauthProviders: oauthProv,
	}
}
