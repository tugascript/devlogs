// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package params

type PaginationQueryParams struct {
	Offset int `json:"offset,omitempty" validate:"min=0"`
	Limit  int `json:"limit,omitempty" validate:"min=1,max=1000"`
}
