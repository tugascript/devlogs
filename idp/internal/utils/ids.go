// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

func Base62UUID() string {
	id := uuid.New()
	return fmt.Sprintf("%022s", Base62Encode(id[:]))
}

func Base64UUID() string {
	id := uuid.New()
	return base64.RawURLEncoding.EncodeToString(id[:])
}

func extractKeyID(keyBytes []byte) string {
	hash := sha256.Sum256(keyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}
