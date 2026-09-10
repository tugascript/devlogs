// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"math/big"
	"regexp"
)

func Base62Encode(bytes []byte) string {
	return new(big.Int).SetBytes(bytes).Text(62)
}

var basicBase64URLRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func BasicBase64URLValidator(s string) bool {
	return basicBase64URLRegex.MatchString(s)
}
