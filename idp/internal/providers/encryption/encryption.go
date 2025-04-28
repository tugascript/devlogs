// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package encryption

import (
	"encoding/base64"
	"log/slog"

	"github.com/tugascript/devlogs/idp/internal/config"
	"github.com/tugascript/devlogs/idp/internal/utils"
)

const logLayer string = utils.ProvidersLogLayer + "/encryption"

type Secret struct {
	kid string
	key []byte
}

type Encryption struct {
	logger           *slog.Logger
	accountSecretKey Secret
	appSecretKey     Secret
	userSecretKey    Secret
	oldSecrets       map[string][]byte
	backendDomain    string
}

func decodeSecret(secret string) Secret {
	decodedKey, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		panic(err)
	}

	return Secret{
		kid: utils.ExtractKeyID(decodedKey),
		key: decodedKey,
	}
}

func NewEncryption(
	logger *slog.Logger,
	cfg config.EncryptionConfig,
	backendDomain string,
) *Encryption {
	oldSecretsMap := make(map[string][]byte)
	for _, s := range cfg.OldSecrets() {
		ds := decodeSecret(s)
		oldSecretsMap[ds.kid] = ds.key
	}

	return &Encryption{
		logger:           logger,
		accountSecretKey: decodeSecret(cfg.AccountSecret()),
		appSecretKey:     decodeSecret(cfg.AppSecret()),
		userSecretKey:    decodeSecret(cfg.UserSecret()),
		oldSecrets:       oldSecretsMap,
		backendDomain:    backendDomain,
	}
}
