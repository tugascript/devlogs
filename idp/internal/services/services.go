// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

import (
	"log/slog"
	"time"

	"github.com/tugascript/devlogs/idp/internal/providers/cache"
	"github.com/tugascript/devlogs/idp/internal/providers/crypto"
	"github.com/tugascript/devlogs/idp/internal/providers/database"
	"github.com/tugascript/devlogs/idp/internal/providers/mailer"
	"github.com/tugascript/devlogs/idp/internal/providers/oauth"
	"github.com/tugascript/devlogs/idp/internal/providers/tokens"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

type Services struct {
	logger           *slog.Logger
	database         *database.Database
	cache            *cache.Cache
	mail             *mailer.EmailPublisher
	jwt              *tokens.Tokens
	crypto           *crypto.Crypto
	oauthProviders   *oauth.Providers
	kekExpDays       time.Duration
	dekExpDays       time.Duration
	jwkExpDays       time.Duration
	accountCCExpDays time.Duration
	appCCExpDays     time.Duration
	userCCExpDays    time.Duration
}

func NewServices(
	logger *slog.Logger,
	database *database.Database,
	cache *cache.Cache,
	mail *mailer.EmailPublisher,
	jwt *tokens.Tokens,
	encrypt *crypto.Crypto,
	oauthProv *oauth.Providers,
	kekExpDays int64,
	dekExpDays int64,
	jwkExpDays int64,
	accountCCExpDays int64,
	appCCExpDays int64,
	userCCExpDays int64,
) *Services {
	return &Services{
		logger:           logger.With(utils.BaseLayer, utils.ServicesLogLayer),
		database:         database,
		cache:            cache,
		mail:             mail,
		jwt:              jwt,
		crypto:           encrypt,
		oauthProviders:   oauthProv,
		kekExpDays:       utils.ToDaysDuration(kekExpDays),
		dekExpDays:       utils.ToDaysDuration(dekExpDays),
		jwkExpDays:       utils.ToDaysDuration(jwkExpDays),
		accountCCExpDays: utils.ToDaysDuration(accountCCExpDays),
		appCCExpDays:     utils.ToDaysDuration(appCCExpDays),
		userCCExpDays:    utils.ToDaysDuration(userCCExpDays),
	}
}
