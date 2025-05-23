// Copyright (c) 2025 Afonso Barracha
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package utils

import "reflect"

func IsEmptyInterface(i interface{}) bool {
	if i == nil {
		return true
	}

	value := reflect.ValueOf(i)

	switch value.Kind() {
	case reflect.Ptr, reflect.Interface:
		return value.IsNil()
	case reflect.Slice, reflect.Map:
		return value.Len() == 0
	case reflect.String:
		return value.Len() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return value.Float() == 0
	case reflect.Bool:
		return !value.Bool() // false is considered empty
	default:
		return false
	}
}
