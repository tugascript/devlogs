// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

func Base62UUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%022s", Base62Encode(id[:])), nil
}

func Base64UUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(id[:]), nil
}

func PrefixedID(prefix string) (string, error) {
	if prefix == "" || len(prefix) > 3 {
		return "", errors.New("prefix must be between 1 and 3 characters")
	}

	id, err := Base64UUID()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s_%s", prefix, id), nil
}
