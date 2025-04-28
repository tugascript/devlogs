// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package tests

import (
	"net/http"
	"testing"
)

func TestHealth(t *testing.T) {
	testCases := []TestRequestCase[string]{
		{
			Name: "Should return 200 OK when calling health",
			ReqFn: func(t *testing.T) (string, string) {
				return "", ""
			},
			ExpStatus: http.StatusOK,
			AssertFn:  func(_ *testing.T, _ string, _ *http.Response) {},
			Path:      "/health",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			PerformTestRequestCase(t, http.MethodGet, tc.Path, tc)
		})
	}
}
