// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

func ToEmptySlice[T any](s []T) []T {
	if s == nil {
		return make([]T, 0)
	}
	return s
}

func MapSlice[T any, U any](s []T, f func(*T) U) []U {
	length := len(s)
	result := make([]U, length)
	if length == 0 {
		return result
	}

	for i, v := range s {
		result[i] = f(&v)
	}

	return result
}
