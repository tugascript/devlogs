// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"log/slog"
	"time"

	"github.com/dgraph-io/ristretto/v2"
	openbao "github.com/openbao/openbao/api/v2"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/crypto"

type Crypto struct {
	logger      *slog.Logger
	opLogical   *openbao.Logical
	localCache  *ristretto.Cache[string, []byte]
	serviceName string
	kekPath     string
	dekTTL      time.Duration
	jwkTTL      time.Duration
}

func NewCrypto(
	logger *slog.Logger,
	op *openbao.Client,
	cache *ristretto.Cache[string, []byte],
	serviceName string,
	encCfg config.CryptoConfig,
) *Crypto {
	return &Crypto{
		logger:      logger.With(utils.BaseLayer, logLayer),
		opLogical:   op.Logical(),
		kekPath:     encCfg.KEKPath(),
		localCache:  cache,
		serviceName: utils.Capitalized(serviceName),
		dekTTL:      time.Duration(encCfg.DEKTTL()) * time.Second,
		jwkTTL:      time.Duration(encCfg.JWKTTL()) * time.Second,
	}
}
