// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

func MapSlice[T any, U any](s []T, f func(*T) U) []U {
	result := make([]U, len(s))

	for i, v := range s {
		result[i] = f(&v)
	}

	return result
}

func MapSliceWithErr[T any, U any, E error](s []T, f func(*T) (U, E)) ([]U, E) {
	result := make([]U, 0, len(s))

	for _, v := range s {
		var err error
		mv, err := f(&v)

		if err != nil {
			if custErr, ok := err.(E); ok {
				return nil, custErr
			}
		}

		result = append(result, mv)
	}

	var err E
	return result, err
}

func MapSliceWithErrorToMap[T any, K comparable, U any, E error](s []T, f func(*T) (K, U, E)) (map[K]U, E) {
	result := make(map[K]U, len(s))

	for _, v := range s {
		var err error
		k, val, err := f(&v)

		if err != nil {
			if custErr, ok := err.(E); ok {
				return nil, custErr
			}
		}

		result[k] = val
	}

	var err E
	return result, err
}
