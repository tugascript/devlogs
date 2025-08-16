// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"log/slog"

	openbao "github.com/openbao/openbao/api/v2"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/crypto"

type Crypto struct {
	logger      *slog.Logger
	opLogical   *openbao.Logical
	serviceName string
	kekPath     string
}

func NewCrypto(
	logger *slog.Logger,
	op *openbao.Client,
	serviceName string,
	encCfg config.CryptoConfig,
) *Crypto {
	return &Crypto{
		logger:      logger.With(utils.BaseLayer, logLayer),
		opLogical:   op.Logical(),
		kekPath:     encCfg.KEKPath(),
		serviceName: utils.Capitalized(serviceName),
	}
}
