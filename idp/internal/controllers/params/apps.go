// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type GetAppsQueryParams struct {
	Limit  int    `validate:"min=1,max=100"`
	Offset int    `validate:"min=0"`
	Name   string `validate:"max=50,min=1,alphanum"`
	Order  string `validate:"oneof=date name"`
}
