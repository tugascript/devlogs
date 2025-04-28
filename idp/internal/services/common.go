// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package services

type SchemaField struct {
	Type     string `json:"type"`
	Unique   bool   `json:"unique"`
	Required bool   `json:"required"`
	Default  any    `json:"default,omitempty"`
}
